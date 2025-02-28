# HIP 0002 - Simplify Sandbox Creation


## Summary

This is a proposal to redefine some user facing APIs for creating sandboxes.

## Motivation

Currently, our user facing API for creating sandboxes is unergonomic and forces users to worry about too much fluff that they shouldn't need to know or worry about. For example, in order to create an uninitalized sandbox, users are forced to provide 4(!) parameters, many of which are not needed in 90% of the cases. And then, they need to call `.evolve()` on it, whatever that means.
```rust
    let mut uninitialized_sandbox = UninitializedSandbox::new(
        hyperlight_host::GuestBinary::FilePath(
            hyperlight_testing::simple_guest_as_string().unwrap(),
        ),
        None, // default configuration
        None, // default run options
        None, // default host print function
    )?;
    let mut multi_use_sandbox: MultiUseSandbox = uninitialized_sandbox.evolve(Noop::default())?;


```

What we should do instead is provide 2 ways of doing things. 

1. The first way of doing should be extremly simple, with very few parameters, and sound defaults, suitable for cases where the user doesn't care about more advanced features.
2. The second way should be for more advanced users, allowing additional more advanced options, should the user need it.

Importantly, these APIs need to be separate functions/method, so as to not force complexity where it's not wanted, like we do currently.

### Goals

- Make it easier for users to use Hyperlight
- Have a simple API for basic use-cases, while still having additional options available for powerusers

## Design details


### Simpler creation of Sandboxes
Currently, `MultiuseSandbox` can only be created form an exiting `UninitializedSandbox`. UninitializedSandbox is "sandbox" that not yet had any initialization code run inside the sandbox. Its only purpose is to be "evolved" into a `MultiUseSandbox` with an optional transition function. The transition function is used to save state to sandbox memory, by allowing guest functions to be called **without having memory reset immediately after the function call**. In practice, this transition function is rarely used, and be removed. The exact same functionality as `evolve` can already be achived using the existing `MultiUseGuestCallContext`, together with using `finish_no_reset`.

I propose we remove `UninitializedSandbox` so that a Sandbox can be created in a single function call. I also propose we rename:
- `MultiuseSandbox` to `Sandbox`. The name was chosen to distingish it from `SingleUseSandbox`, however `SingleUseSandbox` has since been removed. 
- `MultiUseContextGuestCallContext` to `SandboxContext`
- `MultiUseContextCallback` to `SandboxContextCallback`

I propose the following signature for `Sandbox::new`

```rust
pub fn new(guest_binary: GuestBinary) -> Result<Self> 
```
This function would do the functionally equivalent to the current

```rust
UninitializedSandbox::new(
        guest_binary,
        None,
        None,
        None,
    )?.evolve(Noop::default())?;

```

If a user would like to provide the now removed options (SandboxConfiguration, SandboxRunOptions, HostPrinterWriter), I propose we create a new SandboxBuilder:

```rust
    let mut config: SandboxConfiguration = SandboxConfiguration::new();
    config.with_input_data_size(1024);
    config.run_in_process(true);

    let sandbox: Sandbox = SandboxBuilder::new(binary)
        .with_config(&config)
        .with_host_print_writer(|msg| println!("{}", msg))
        .with_host_function("sleep_5_secs", || {
            thread::sleep(Duration::from_secs(5));
            Ok(())
        })
        .build()?;
```
and that we remove and consolidate `SandboxRunOptions` into `SandboxConfiguration`, so we only have 1 config struct.

This HIP is only concerned with user facing changes. 



