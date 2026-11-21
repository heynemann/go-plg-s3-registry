package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bytedance/sonic"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/heynemann/go-plg-s3-registry/dataplane"
	"github.com/heynemann/go-plg-s3-registry/examples/rewards/contract"
	api "github.com/heynemann/go-plg-s3-registry/examples/rewards/gen"
)

type rewards struct {
	host     *dataplane.Host[contract.Rule]
	db       *sql.DB
	draining atomic.Bool
}

var _ api.StrictServerInterface = (*rewards)(nil)

func (s *rewards) Readiness(_ context.Context, _ api.ReadinessRequestObject) (api.ReadinessResponseObject, error) {
	status := s.host.Status()
	out := api.Readiness{Ready: status.Ready && !s.draining.Load()}
	out.Effective.Decision = status.Effective.Decision
	out.Effective.Generation = status.Effective.Generation
	out.Effective.Epoch = status.Effective.Epoch
	if !out.Ready {
		return api.Readiness503JSONResponse(out), nil
	}
	return api.Readiness200JSONResponse(out), nil
}

func (s *rewards) GetDelivery(ctx context.Context, req api.GetDeliveryRequestObject) (api.GetDeliveryResponseObject, error) {
	d, err := readDelivery(ctx, s.db, req.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return api.GetDelivery404ApplicationProblemPlusJSONResponse(problem(ctx, http.StatusNotFound, "about:blank", "delivery not found")), nil
	}
	if err != nil {
		return nil, err
	}
	return api.GetDelivery200JSONResponse{DeliveryJSONResponse: api.DeliveryJSONResponse(d)}, nil
}

func (s *rewards) ReserveDelivery(ctx context.Context, req api.ReserveDeliveryRequestObject) (api.ReserveDeliveryResponseObject, error) {
	d, identical, err := readReservation(ctx, s.db, req.ID, *req.Body)
	if errors.Is(err, sql.ErrNoRows) {
		receipt, err := s.host.Select([]byte(req.Body.Subject), map[string]any{"region": req.Body.Region})
		if err != nil {
			return api.ReserveDelivery503ApplicationProblemPlusJSONResponse(unavailable(ctx, err)), nil
		}
		created, err := insertDelivery(ctx, s.db, req.ID, *req.Body, receipt)
		if err != nil {
			return nil, err
		}
		if created {
			return api.ReserveDelivery201JSONResponse{ID: req.ID, Status: api.Pending, PluginDigest: receipt.Digest}, nil
		}
		// Another request reserved this ID; its original payload and pin win.
		d, identical, err = readReservation(ctx, s.db, req.ID, *req.Body)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if !identical {
		return api.ReserveDelivery409ApplicationProblemPlusJSONResponse(problem(ctx, http.StatusConflict, "about:blank", "delivery ID already has a different reservation")), nil
	}
	return api.ReserveDelivery200JSONResponse{DeliveryJSONResponse: api.DeliveryJSONResponse(d)}, nil
}

func (s *rewards) AttemptDelivery(ctx context.Context, req api.AttemptDeliveryRequestObject) (api.AttemptDeliveryResponseObject, error) {
	d, tier, data, err := readAttempt(ctx, s.db, req.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return api.AttemptDelivery404ApplicationProblemPlusJSONResponse(problem(ctx, http.StatusNotFound, "about:blank", "delivery not found")), nil
	}
	if err != nil {
		return nil, err
	}
	if d.Status == api.Pending {
		var receipt dataplane.Receipt
		if err := sonic.ConfigStd.Unmarshal(data, &receipt); err != nil {
			return nil, err
		}
		var accepted bool
		callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		// Always replay the pin from SQLite. The rule is a pure computation;
		// the transaction below is the only place that can issue an award.
		err := s.host.InvokeRetry(callCtx, receipt, func(rule contract.Rule) error {
			var err error
			accepted, err = rule.Accept(callCtx, tier)
			return err
		})
		cancel()
		if err != nil {
			return api.AttemptDelivery503ApplicationProblemPlusJSONResponse(unavailable(ctx, err)), nil
		}
		d, err = completeDelivery(ctx, s.db, d.ID, accepted)
		if err != nil {
			return nil, err
		}
	}
	return api.AttemptDelivery200JSONResponse{DeliveryJSONResponse: api.DeliveryJSONResponse(d)}, nil
}

type requestIDKey struct{}

func problem(ctx context.Context, status int, typ, detail string) api.Problem {
	id, _ := ctx.Value(requestIDKey{}).(string)
	out := api.Problem{Type: typ, Title: http.StatusText(status), Status: status, RequestID: id}
	if detail != "" {
		out.Detail = &detail
	}
	return out
}

func unavailable(ctx context.Context, err error) api.Problem {
	switch {
	case errors.Is(err, dataplane.ErrQuarantined):
		return problem(ctx, http.StatusServiceUnavailable, "urn:rewards:quarantined", "the selected rule is quarantined")
	case errors.Is(err, dataplane.ErrStale):
		return problem(ctx, http.StatusServiceUnavailable, "urn:rewards:stale", "registry authority is not fresh")
	default:
		return problem(ctx, http.StatusServiceUnavailable, "urn:rewards:blocked", "the rule is not available for this delivery")
	}
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = sonic.ConfigStd.NewEncoder(w).Encode(problem(r.Context(), status, "about:blank", detail))
}

func badRequest(w http.ResponseWriter, r *http.Request, _ error) {
	writeProblem(w, r, http.StatusBadRequest, "request does not match the API contract")
}

func internalError(w http.ResponseWriter, r *http.Request, _ error) {
	writeProblem(w, r, http.StatusInternalServerError, "")
}

func init() {
	// The validator's default JSON decoder accepts the first value even when
	// another follows. Require a single JSON value, as the contract specifies.
	openapi3filter.RegisterBodyDecoder("application/json", func(body io.Reader, _ http.Header, _ *openapi3.SchemaRef, _ openapi3filter.EncodingFn) (any, error) {
		dec := sonic.ConfigStd.NewDecoder(body)
		dec.UseNumber()
		var value any
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			return nil, errors.New("expected a single JSON value")
		}
		return value, nil
	})
}

func (s *rewards) handler(ctx context.Context) (http.Handler, error) {
	spec, err := api.GetSwagger()
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(ctx); err != nil {
		return nil, err
	}
	router, err := gorillamux.NewRouter(spec)
	if err != nil {
		return nil, err
	}
	strict := api.NewStrictHandlerWithOptions(s, nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: badRequest, ResponseErrorHandlerFunc: internalError,
	})
	handler := api.HandlerWithOptions(strict, api.StdHTTPServerOptions{ErrorHandlerFunc: badRequest})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := rand.Text()
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("Cache-Control", "no-store")
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id))

		route, params, err := router.FindRoute(r)
		switch {
		case errors.Is(err, routers.ErrMethodNotAllowed):
			// Preserve the protocol's Allow header while using a problem body.
			var allow []string
			probe := *r
			for _, method := range [...]string{http.MethodGet, http.MethodPost, http.MethodPut} {
				probe.Method = method
				if _, _, err := router.FindRoute(&probe); err == nil {
					allow = append(allow, method)
				}
			}
			w.Header().Set("Allow", strings.Join(allow, ", "))
			writeProblem(w, r, http.StatusMethodNotAllowed, "")
			return
		case err != nil:
			writeProblem(w, r, http.StatusNotFound, "")
			return
		}
		// kin-openapi matches encoded segments; validate their decoded values,
		// which are what the generated net/http handlers receive.
		for key, part := range params {
			params[key], err = url.PathUnescape(part)
			if err != nil {
				badRequest(w, r, err)
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := openapi3filter.ValidateRequest(r.Context(), &openapi3filter.RequestValidationInput{
			Request: r, PathParams: params, Route: route,
		}); err != nil {
			badRequest(w, r, err)
			return
		}
		if route.Operation.RequestBody == nil && (r.ContentLength != 0 || len(r.TransferEncoding) != 0) {
			badRequest(w, r, nil)
			return
		}
		handler.ServeHTTP(w, r)
	}), nil
}
