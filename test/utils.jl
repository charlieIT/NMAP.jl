function isdiff(a, b) :: Bool
    if typeof(a) !== typeof(b) return true end
    if a === b return false end
    if isempty(fieldnames(typeof(a)))
        return a != b
    end
    for prop in fieldnames(typeof(a))
        try
            if isdiff(getfield(a, prop), getfield(b, prop))
                return true
            end
        catch;
            if getfield(a, prop) != getfield(b, prop)
                return true
            end
        end
    end
    return false
end
