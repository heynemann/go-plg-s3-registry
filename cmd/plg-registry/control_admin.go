package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/heynemann/go-plg-s3-registry/internal/registry"
	"github.com/heynemann/go-plg-s3-registry/internal/rollout"
)

func (o *controlOptions) publisherStatus() *cobra.Command {
	return o.command("status", "Show the current publication binding and its exact revision", func(ctx context.Context, cmd *cobra.Command) error {
		s, err := o.connect(ctx, cmd, "")
		if err != nil {
			return err
		}
		source, err := s.sourceRegistry()
		if err != nil {
			return err
		}
		binding, revision, err := source.PublisherStatus(ctx, s.service.Scope.Plugin)
		if err != nil {
			return err
		}
		return o.publisherResult(cmd, s, "current", binding, revision, nil)
	})
}

func (o *controlOptions) publisherChange(action string) *cobra.Command {
	var path, requestPath string
	var request struct {
		Expected  string              `json:"expected"`
		Publisher *registry.Publisher `json:"publisher,omitempty"`
	}
	short := "Suspend publication and list affected digests without changing invocation authority"
	if action == "rotate" {
		short = "Replace the publication authority without invalidating admitted artifacts"
	}
	cmd := o.command(action, short, func(ctx context.Context, cmd *cobra.Command) error {
		if err := readOperationInput(cmd, requestPath, &request, "expected", "publisher"); err != nil {
			return err
		}
		if request.Expected == "" {
			return invalidInput("an expected publication binding digest is required")
		}
		if action == "rotate" {
			if request.Publisher == nil {
				request.Publisher = new(registry.Publisher)
				if err := readInput(path, request.Publisher); err != nil {
					return err
				}
			}
			if err := o.global.checkKeyMode(request.Publisher.KeyID); err != nil {
				return err
			}
		} else if request.Publisher != nil {
			return invalidInput("a replacement publisher is only applicable to rotation")
		}
		s, err := o.connect(ctx, cmd, publisherAdmin)
		if err != nil {
			return err
		}
		source, err := s.sourceRegistry()
		if err != nil {
			return err
		}
		var binding registry.Registration
		var revision, status string
		var affected []string
		plugin := s.service.Scope.Plugin
		if action == "rotate" {
			binding, revision, err = source.Rotate(ctx, plugin, request.Expected, *request.Publisher)
			status = "rotated"
		} else {
			binding, revision, affected, err = source.Suspend(ctx, plugin, request.Expected)
			status = "suspended"
		}
		if err != nil {
			if errors.Is(err, registry.ErrConflict) {
				if _, current, readErr := source.PublisherStatus(ctx, plugin); readErr == nil {
					return &controlError{err: err, current: current}
				}
			}
			return err
		}
		return o.publisherResult(cmd, s, status, binding, revision, affected)
	})
	cmd.Flags().StringVar(&request.Expected, "expected", "", "exact current publication binding digest")
	if action == "rotate" {
		cmd.Flags().StringVar(&path, "publisher", "", "JSON replacement publisher binding")
	}
	cmd.Flags().StringVar(&requestPath, "request", "", "JSON request with expected and (for rotation) publisher")
	return cmd
}

func (o *controlOptions) publisherResult(cmd *cobra.Command, s controlSession, status string, binding registry.Registration, revision string, affected []string) error {
	var affectedDigests *[]string
	if status == "suspended" {
		if affected == nil {
			affected = []string{}
		}
		affectedDigests = &affected
	}
	result := struct {
		scopedResult
		Status          string                `json:"status"`
		Registration    registry.Registration `json:"registration"`
		Revision        string                `json:"revision"`
		AffectedDigests *[]string             `json:"affected_digests,omitempty"`
	}{s.resultScope(), status, binding, revision, affectedDigests}
	if err := o.output(cmd, result, "%s publication binding for %s: %s (suspended: %t)\n", status, binding.Plugin, revision, binding.Suspended); err != nil {
		return err
	}
	if o.global.output == "text" {
		for _, digest := range affected {
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), digest); err != nil {
				return err
			}
		}
	}
	return nil
}

func (o *controlOptions) recoveryEvidence() *cobra.Command {
	return o.command("evidence", "Read a verified head checkpoint for independent recording", func(ctx context.Context, cmd *cobra.Command) error {
		s, err := o.connect(ctx, cmd, "")
		if err != nil {
			return err
		}
		decision, err := s.service.Current(ctx)
		if err != nil {
			return err
		}
		checkpoint := rollout.RecoveryEvidence{Scope: decision.Scope, Generation: decision.Generation, Decision: decision.ID}
		return o.output(cmd, struct {
			Schema     int                      `json:"schema_version"`
			Checkpoint rollout.RecoveryEvidence `json:"checkpoint"`
		}{1, checkpoint}, "%s/%s epoch %s generation %d decision %s; record and corroborate outside the registry bucket\n",
			decision.Scope.Environment, decision.Scope.Plugin, decision.Scope.Epoch, decision.Generation, decision.ID)
	})
}

func (o *controlOptions) reconcile() *cobra.Command {
	var path string
	cmd := o.command("reconcile", "Verify the deployment-pinned checkpoint and commit a new fenced epoch", func(ctx context.Context, cmd *cobra.Command) error {
		if err := readOperationInput(cmd, path, &struct{}{}); err != nil {
			return err
		}
		s, err := o.connect(ctx, cmd, recovererRole)
		if err != nil {
			return err
		}
		if s.service.Recovery == nil {
			return invalidInput("reconcile requires a recovery checkpoint pinned in the trusted deployment")
		}
		decision, err := s.service.Recover(ctx, *s.service.Recovery, s.actor)
		if err != nil {
			return s.onConflict(ctx, err)
		}
		return o.applied(cmd, decision)
	})
	cmd.Flags().StringVar(&path, "request", "", "empty JSON request; checkpoint must come from trusted deployment")
	return cmd
}
