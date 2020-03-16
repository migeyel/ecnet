Tasks:clean()

Tasks:minify "minify" {
    input = "build/ecnet.lua",
    output = "build/ecnet.min.lua"
}

Tasks:require "main" {
    include = "ecnet/*.lua",
    startup = "ecnet/ecnet.lua",
    output = "build/ecnet.lua"
}

Tasks:Task "build" {"clean", "minify"} :Description "Main build task"

Tasks:Default "main"
