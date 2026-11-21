local Rule = {}

function Rule:Accept(value)
  return value == "gold"
end

function Create()
  return setmetatable({}, { __index = Rule })
end
