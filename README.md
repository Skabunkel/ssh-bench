# What is this?
*EDIT 2026-06-10*

STILL NOT RECOMMENDED FOR PRODUCTION USE, but i have decided that i like this code enough to try and fix it.


*Original text*

This is *VIBECODED*. *Not for production use*, in my professinal opinion trusting this is like trusting a *pressure sensitive nuke as a doorstop*. USE [russh](https://github.com/Eugeny/russh) instead.

This is one of my personal AI benchmarks, that i have used. Because its difficult and im a perticular taskmaster. 

## Why not use it for prod?
... its vibecode? Okay list bellow.

* No secure zeroing of memory, passwords etc will remain in RAM.
* No DDos protection.
* Unsecure password evaluation(timing side channel sensitive).
* Attackers can do as many password retries as possible.
* No fuzzing.
* No peer review. This is all trust me bro.

It works which is impressive but its not safe.

## Things i like about it.
These things can easily be fixed in russh, so but this is things the AI did well with just a claude.md as input.

* Used existing pure rust libs for crypto.
* Relativly few dependencies.

I have seen projects ending up with about 700 dependencies.

* traits for handling auth eg ServerAuthHandler and ClientAuthHandler. 

Instead of having a huge trait for everything like in russh we have a some thin traits for handling auth.

* allows me to register a Shell and ExecHandler and just work in its context, i dont need to do any internal wiring.

Example from code... why did it call this cat and not echo?
```rust
/// Demo in-process handler: echo stdin back to stdout (a stand-in for sftp/git/etc.).
struct CatHandler;

impl ExecHandler for CatHandler {
    fn run(self: Arc<Self>, _command: Box<str>, session: ChannelSession) -> HandlerFuture {
        Box::pin(async move {
            let (mut reader, mut writer) = session.split();
            let _ = tokio::io::copy(&mut reader, &mut writer).await;
            0
        })
    }
}

fn build_context() -> ExecContext {
    let ctx = ExecContext::new()
        // In-process command: `ssh host cat` echoes its stdin.
        .on_exec("cat", CatHandler);

    ...
}
```
Building rsync or sftp would be really nice, but its just minor thing honestly.

* It uses only 0.5-1.2MiB of RAM on my machine while running a debug build.

I feel like someone who knows what they are doing would have it run in a little bit less, but its very good. I expected way worse.

When having several clients connected it didnt increase too much, about 0.5MiB when a the first client connected and 0.3-0.1 MiB with subsequent connections.
Starting at 1.1 MiB getting to 2MiB with 4 clients.

* It's compatable with openSSH.

I was worried it would not be, but it keep testing compatability consistalty starting at milestone 2 without prompting.

* No supply chain risk.

It used older none deprecated packages.

## What i dont like

*Added 2026-06-10*
* The connection loop is handled buy user code.

*Original*
* Some old packages.

None of them where deprecated, and we dont need to worry about a supply chain attack but it would be nice if it added them via `cargo add` instead of writing the file by hand. 

SHA2 has a version 0.11, Claude used 0.10

ssh-encoding has a 0.3 Claude used 0.2

etc.

* In the ssh-io it ties itself to TcpStream, its one prompt away to fix but meh.

It should have used something like `S: AsyncRead + AsyncWrite + Unpin` that way the local tests would be in memory with `tokio::io::duplex`
It then it would be easy to write tests for diffrent crypto setups and client side fuzzing.

* The server swallows the first input from the a real ssh client. 

The when the first client that connects it will eat the first input, but still process it. Resulting in the first letter becoming invisible when using normal `ssh`.

# Prompt and stearing.
I Copied a CLAUDE.md from another project i had created a while ago.
```
Please create a SSH server in pure rust, you may not use russh or thrussh, they contain none rust code. Focus on implementing features such as Shell and Exec.
```
It asked if it was allowed to use crates from https://github.com/RustCrypto like sha2 and SSH and i said yes.

After planning it had come out with 5 milestones.
* M0 - Workspace scaffold + codec + framing
* M1 - Secure transport (KEX + cipher)
* M2 - Authentication
* M3 - Connection layer + Exec
* M4 - Shell
* M5 - Hardening + interop tests

After milestone 4 i hit my session limit, and spent some time reading through it.
I when my session reset, i told it 
`You should use Box<str> or Cow<str>, instead of String unless you really need to mutate the value.`

It flew off to replace all instances of String with Box<str> and atleast one with a Cow<'static, str>, i do however feel like it could have used Cow more.
Then i told claude 
`i didnt like the Shell and ExecHandler, becasue it had made the assumption that the system should always interact with the os. i want in process support.`

It ran off and solved it quite nicly i think with a ExecContext with handlers for shell and Exec commands.
After that i told claude to move on to M5.

# Summary
I think this was a good test, it created code i would use... if i trusted it.
But im biasd, I crated the CLAUDE.md its building the code in a way i perfer, its not perfect but meh.

Please come with input.
