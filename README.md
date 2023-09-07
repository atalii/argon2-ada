# Argon2 in Ada

## Overview

This provides access to the Argon2 API in a safe and convenient wrapper. Note
that it is a *binding* to the C-based argon2 library rather than a pure-Ada
reimplementation.

## Usage

```ada
package Hash is new Argon2Ada.Hasher
    (Output_Len => 128, Pass_Len => 64);

-- Parameters here are arbitrary; don't blindly copy them!
Config :=
    (Time_Cost => 1, Mem_Cost => 64, Lanes => 4,
    Version => Argon2Ada.Version_13,
    Alg_Type => ID,
    Flags => Argon2Ada.Wipe_None);

Result := Config.Hash (Pass, Salt);
```

See argon2ada.ads for everything else.

## Building

```sh
$ gprbuild -P argon2ada
```

## Testing

```sh
$ gprbuild -P tests
$ ./bin/tests
```

## Get Involved?

This isn't too complex a project, but I would love another pair of eyes on the
code. My Ada is rough and cryptography is hard. In the short term, I'm looking
to increase test coverage, in the medium term, proving type safety with SPARK is
on the agenda, and it may prove useful to potentially automatically generate
`Argon2Ada.Raw` over the long term. If you want to help with any of that or
review the code that's already here, I would be very grateful.
