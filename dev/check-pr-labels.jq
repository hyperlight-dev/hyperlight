.labels | map(.name) as $labels |
[$labels[] | . as $label |
    if startswith("kind/") and . != "kind/documentation" then
        ([$aliases[0] | to_entries[] |
            select(.value | index($label)) | .key][0] // $label)
    elif startswith("C-") then .
    else empty end
] | unique | length as $count |
if $count == 1 then true
elif $count == 0 and ($labels | index("kind/documentation")) != null then true
else error("PR must have exactly one C- category, found \($count). Documentation also needs a category.")
end
