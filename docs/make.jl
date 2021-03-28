using Documenter
using Nghttp2

makedocs(
    sitename = "Nghttp2",
    format = Documenter.HTML(),
    modules = [Nghttp2]
)

# Documenter can also automatically deploy documentation to gh-pages.
# See "Hosting Documentation" and deploydocs() in the Documenter manual
# for more information.
#=deploydocs(
    repo = "<repository url>"
)=#
