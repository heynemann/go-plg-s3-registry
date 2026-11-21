local Rule = {}

function Rule:Accept(value)
  return value == "gold" or value == "silver"
end

function Create()
  return setmetatable({}, { __index = Rule })
end
