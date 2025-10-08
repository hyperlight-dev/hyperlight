# How to use FlatBuffers

> Note: the last generation of the flatbuffer code was with done with flatc version 25.9.23 (i.e., the last version as of Oct 2nd, 2025).

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
