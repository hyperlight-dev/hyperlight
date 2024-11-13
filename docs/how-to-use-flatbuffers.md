# How to use FlatBuffers

Flatbuffers is used to serialize and deserialize some data structures.

Schema files are used to define the data structures and are used to generate the code to serialize and deserialize the data structures.

Those files are located in the [`schema`](../src/schema) directory.

Code generated from the schema files is checked in to the repository, therefore you only need to generate the code if you change an existing schema file or add a new one. You can find details on how to update schema files [here](https://google.github.io/flatbuffers/flatbuffers_guide_writing_schema.html).

## Generating code

We use [flatc](https://google.github.io/flatbuffers/flatbuffers_guide_using_schema_compiler.html) to generate rust code.

We recommend building `flatc` from source. To generate rust code, use

```console
just gen-all-fbs-rust-code
```

### Note about generated code

Because we invoke `flatc` multiple times when generating the Rust code, the `mod.rs` generated in `./src/hyperlight_common/src/flatbuffers` is overwritten multiple times and will likely be incorrect. Make sure to manually inspect and if necessary update this file before continuing with your changes as certain modules might be missing. After fixing `mod.rs`, you might need to re-run `just fmt`, since it might not have applied to all generated files if your `mod.rs` was invalid.

>`flatc` does support passing multiple schema files (e.g. it is possible to pass `.\src\schema\*.fbs`), so we could regenerate all the files each time a change was made, however that generates incorrect code (see [here](https://github.com/google/flatbuffers/issues/6800) for details).
