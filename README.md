# onion-vanity-address 🧅

This tool generates Tor Onion Service v3 [vanity address](https://community.torproject.org/onion-services/advanced/vanity-addresses/) with a specified prefix.

It can also generate vanity [client authorization](https://community.torproject.org/onion-services/advanced/client-auth/) keypair.

Compared to [similar tools](#similar-tools), it uses the [fastest search algorithm](#the-fastest-search-algorithm) 🚀

## What's been added in this fork

This fork adds several practical improvements for generating and managing multiple vanity Onion Service keys:

* The tool now keeps searching until it has found three matching Onion Service addresses by default.
* Use `--count` to choose how many matches to find before stopping.

  * Example: `--count 1`
  * Example: `--count 5`
* Normal Tor output now writes each generated Onion Service keypair to its own directory named after the hostname.
* Each normal Tor output directory contains the standard Onion Service files:

  * `hostname`
  * `hs_ed25519_public_key`
  * `hs_ed25519_secret_key`
* Use `--start9` to output the private key in the Start9 StartOS Tor plugin format (base64 encoded).
* Start9 output writes one file per generated hostname.
* Each Start9 output file is named after the hostname and contains only the 88-character base64-encoded expanded secret key.
* Allows optional suffix and combined searches (roughly 10x slower than prefix searches, [see below](#suffix-and-combined-searches)).
* The live search status now updates in-place in the terminal instead of showing no progress during the process.
* The progress report shows:

  * elapsed search time
  * total attempts tried
  * attempts per second
  * how many matching keys have been found
  * how many are still remaining
* When a matching key is found, the tool prints it immediately while continuing the search.
* Large numbers are now shown in a short readable format.

  * Example: `56.4M attempts/s`
  * Example: `75.5B` total attempts

## Usage

Install the tool locally and run:

```sh
go install github.com/xannythepleb/onion-vanity-address@latest
```

By default the tool keeps searching until it has found three matching Onion Service addresses:

```console
$ onion-vanity-address test t3st testaddr
Searching test,t3st,testaddr | elapsed 10s | tried 564.0M | 56.4M attempts/s | found 0/3 | remaining 3
Found test... testabc...onion (1/3) after 12s and 676.8M attempts (56.4M attempts/s)
Searching test,t3st,testaddr | elapsed 20s | tried 1.1B | 56.4M attempts/s | found 1/3 | remaining 2
Found t3st... t3stxyz...onion (2/3) after 31s and 1.7B attempts (56.4M attempts/s)
Searching test,t3st,testaddr | elapsed 40s | tried 2.3B | 56.4M attempts/s | found 2/3 | remaining 1
Found test... testdef...onion (3/3) after 45s and 2.5B attempts (56.4M attempts/s)
Wrote Tor service files to testabc...onion/
Wrote Tor service files to t3stxyz...onion/
Wrote Tor service files to testdef...onion/
```

The live `Searching ...` line is updated in-place while the tool is running. It is shown across multiple lines above only to demonstrate how the progress report changes over time.

Use `--count` to choose how many matching addresses to find before stopping:

```console
$ onion-vanity-address --count 1 allium
Searching allium | elapsed 10s | tried 485.3M | 48.5M attempts/s | found 0/1 | remaining 1
Found allium... alliumdye3it7ko4cuftoni4rlrupuobvio24ypz55qpzjzpvuetzhyd.onion (1/1) after 12s and 559.0M attempts (48.5M attempts/s)
Wrote Tor service files to alliumdye3it7ko4cuftoni4rlrupuobvio24ypz55qpzjzpvuetzhyd.onion/
```

Normal Tor output is written as a directory named after the hostname:

```text
alliumdye3it7ko4cuftoni4rlrupuobvio24ypz55qpzjzpvuetzhyd.onion/
├── hostname
├── hs_ed25519_public_key
└── hs_ed25519_secret_key
```

The `hostname` file contains the `.onion` address.

The `hs_ed25519_public_key` and `hs_ed25519_secret_key` files can be used as the Onion Service key files expected by Tor.

Use `--start9` to write the private key in the 88-character base64 format expected by Start9 StartOS's Tor plugin UI:

```console
$ onion-vanity-address --start9 --count 1 allium
Searching allium | elapsed 10s | tried 485.3M | 48.5M attempts/s | found 0/1 | remaining 1
Found allium... alliumdye3it7ko4cuftoni4rlrupuobvio24ypz55qpzjzpvuetzhyd.onion (1/1) after 12s and 559.0M attempts (48.5M attempts/s)
Wrote Start9 key to alliumdye3it7ko4cuftoni4rlrupuobvio24ypz55qpzjzpvuetzhyd.onion
```

That file contains only the expanded secret key, base64-encoded.

It should be 88 characters long and end in `==`.

Example Start9 output file:

```text
alliumdye3it7ko4cuftoni4rlrupuobvio24ypz55qpzjzpvuetzhyd.onion
```

Example file contents:

```text
YEQm98uujS4eH1tY6S9t0ThKbw8KzVwA6Ue3wAjOfE6cfq1Uxx4XHJb9x7oN0r2gO6rAVybr5kAy5VnPTrm9xQ==
```

You can also use `--start9` with multiple prefixes:

```console
$ onion-vanity-address --start9 --count 3 test t3st testaddr
Searching test,t3st,testaddr | elapsed 10s | tried 564.0M | 56.4M attempts/s | found 0/3 | remaining 3
Found test... testabc...onion (1/3) after 12s and 676.8M attempts (56.4M attempts/s)
Searching test,t3st,testaddr | elapsed 20s | tried 1.1B | 56.4M attempts/s | found 1/3 | remaining 2
Found t3st... t3stxyz...onion (2/3) after 31s and 1.7B attempts (56.4M attempts/s)
Searching test,t3st,testaddr | elapsed 40s | tried 2.3B | 56.4M attempts/s | found 2/3 | remaining 1
Found testaddr... testaddrabc...onion (3/3) after 2m8s and 7.2B attempts (56.4M attempts/s)
Wrote Start9 key to testabc...onion
Wrote Start9 key to t3stxyz...onion
Wrote Start9 key to testaddrabc...onion
```

Or use the Docker image:

```sh
docker pull ghcr.io/xannythepleb/onion-vanity-address:latest
docker run ghcr.io/xannythepleb/onion-vanity-address:latest --count 1 allium
```

With Start9 output:

```sh
docker run ghcr.io/xannythepleb/onion-vanity-address:latest --start9 --count 1 allium
```

### Multiple prefixes

The tool can check multiple prefixes simultaneously:

```sh
onion-vanity-address --count 3 zwiebel cipolla cebolla
```

Example output:

```console
$ onion-vanity-address --count 3 zwiebel cipolla cebolla
Searching zwiebel,cipolla,cebolla | elapsed 10s | tried 486.9M | 48.7M attempts/s | found 0/3 | remaining 3
Found cipolla... cipollaabc...onion (1/3) after 29s and 1.4B attempts (48.7M attempts/s)
Searching zwiebel,cipolla,cebolla | elapsed 40s | tried 1.9B | 48.7M attempts/s | found 1/3 | remaining 2
Found cebolla... cebollaxyz...onion (2/3) after 1m5s and 3.2B attempts (48.7M attempts/s)
Searching zwiebel,cipolla,cebolla | elapsed 1m20s | tried 3.9B | 48.7M attempts/s | found 2/3 | remaining 1
Found zwiebel... zwiebeldef...onion (3/3) after 1m53s and 5.5B attempts (48.7M attempts/s)
Wrote Tor service files to cipollaabc...onion/
Wrote Tor service files to cebollaxyz...onion/
Wrote Tor service files to zwiebeldef...onion/
```

It will output the first three onion addresses that start with any of the specified prefixes.

Use `--count` to change this behaviour:

```sh
onion-vanity-address --count 5 zwiebel cipolla cebolla
```

When searching for multiple prefixes of varying lengths, shorter prefixes will appear more often. For example `test` will generate three addresses virtually instantly on a modern laptop CPU.

### Suffix and combined searches

Use `--suffix` to search for addresses ending with one of the supplied patterns instead of starting with them:

```console
$ onion-vanity-address --suffix --count 1 pleb
Warning: suffix matching is slower because each candidate must be fully encoded before it can be checked.
Searching suffix pleb | elapsed 10s | tried 120.0M | 12.0M attempts/s | found 0/1 | remaining 1
Found ...pleb abcxyz...pleb.onion (1/1) after 1m12s and 864.0M attempts (12.0M attempts/s)
Wrote Tor service files to abcxyz...pleb.onion/
```

Suffix matching checks the address body before `.onion`, so `--suffix pleb` looks for `...pleb.onion`. Because it must compute the entire address (key) first, it is significantly slower than the default prefix behaviour.

Use `--both` to search for addresses that start with one pattern and end with another. It takes exactly two positional arguments: the prefix first, then the suffix:

```console
$ onion-vanity-address --both --count 1 pleb sats
Warning: --both requires each result to match the supplied prefix and suffix. This can take much longer than searching only one side.
Searching prefix pleb + suffix sats | elapsed 10s | tried 120.0M | 12.0M attempts/s | found 0/1 | remaining 1
```

`--both` is much harder than prefix-only or suffix-only matching because the probability is roughly multiplied by both pattern lengths. For example, a four character prefix plus a four character suffix is broadly comparable to searching for an eight character vanity constraint. I don't recommend using it unless you have very powerful hardware or are using a very powerful VPS.

The tool warns you these options are much slower when you use either the `--suffix` or `--both` flag.

### Client authorization

To generate vanity [client authorization](https://community.torproject.org/onion-services/advanced/client-auth/) keypairs use the `--client` flag:

```console
$ onion-vanity-address --client --count 1 LEMON
Found LEMON... (1/1) in 0s after 15.0M attempts (63.6M attempts/s)
---
public_key: LEMON7P5L7FEZZEJJGQTC3PDFRHEOOBP3H2XXHRFQSD72OKKEE5Q
private_key: AAADDFICRR46KLA52KV2QRIN6GUWIPEIVZZZUVZLC5UVE53QNMTA
```

Client authorization keypairs are still printed to standard output.

The `--start9` flag is only for Onion Service private key output and cannot be used together with `--client`.

Then add the public key to the `authorized_clients` directory:

```console
$ echo descriptor:x25519:LEMON7P5L7FEZZEJJGQTC3PDFRHEOOBP3H2XXHRFQSD72OKKEE5Q > /var/lib/tor/hidden_service/authorized_clients/lemon.auth
$ systemctl reload tor
```

To access the service via Tor Browser provide it the private key:

```text
┌────────────────────────────────┬───────────────────────────────────────────
│ 🛈 Authentication required   🗙 │ ＋
├────────────────────────────────┴───────────────────────────────────────────
│ ← → ⟳ 🛈 🗝 alliumdye3it7ko4cuftoni4rlrupuobvio24ypz55qpzjzpvuetzhyd.onion
├───────────────────────────────────────────────────────┬────────────────────
│                                                       │
│  The onion site allium...etzhyd.onion is requesting   │
│  that you authenticate.                               │
│                                                       │
│  ╭─────────────────────────────────────────────────╮  │
│  │ AAADDFICRR46KLA52KV2QRIN6GUWIPEIVZZZUVZLC5UVE...│  │
│  ╰─────────────────────────────────────────────────╯  │
│   □ Remember this key          ╭──────────╮ ╭──────╮  │
│                                │  Cancel  │ │  OK  │  │
│                                ╰──────────╯ ╰──────╯  │
╰───────────────────────────────────────────────────────╯
```

To see all flags and usage examples run:

```sh
onion-vanity-address --help
```

## Performance

The tool checks around 45,000,000 keys per second on a laptop:

```console
$ onion-vanity-address --timeout 20s --count 1 goodluckwiththisprefix
Searching goodluckwiththisprefix | elapsed 10s | tried 480.1M | 48.0M attempts/s | found 0/1 | remaining 1
Searching goodluckwiththisprefix | elapsed 20s | tried 959.8M | 48.0M attempts/s | found 0/1 | remaining 1
Stopped searching [goodluckwiththisprefix]... after 20s and 959.8M attempts (48.0M attempts/s)
```

which is around 2x faster than `mkp224o`:

```console
$ timeout 20 docker run ghcr.io/cathugger/mkp224o:master -s -y goodluckwiththisprefix
sorting filters... done.
filters:
        goodluckwiththisprefix
in total, 1 filter
using 8 threads
>calc/sec:18497645.320881, succ/sec:0.000000, rest/sec:79.315507, elapsed:0.100863sec
>calc/sec:18884429.043617, succ/sec:0.000000, rest/sec:0.000000, elapsed:10.108983sec
```

In practice, it finds a 6-character prefix within a minute.

Each additional character increases search time by a factor of 32.

## Kubernetes

Run distributed vanity address search in a Kubernetes cluster using the [demo-k8s.yaml](demo-k8s.yaml) manifest without exposing the secret key to the cluster.

This distributed mode searches for an offset from a starting public key. Once the cluster finds a matching offset, apply that offset locally to the corresponding secret key.

```console
$ # Locally generate one secure starting keypair
$ onion-vanity-address --count 1 start
Searching start | elapsed 1s | tried 43.4M | 43.4M attempts/s | found 0/1 | remaining 1
Found start... startxxytwan7gfm6ojs6d2auwhwjhysjz3c5j2hd7grlokzmd4reoqd.onion (1/1) after 1s and 43.4M attempts (43.4M attempts/s)
Wrote Tor service files to startxxytwan7gfm6ojs6d2auwhwjhysjz3c5j2hd7grlokzmd4reoqd.onion/

$ # The generated directory contains:
$ ls startxxytwan7gfm6ojs6d2auwhwjhysjz3c5j2hd7grlokzmd4reoqd.onion/
hostname
hs_ed25519_public_key
hs_ed25519_secret_key

$ # Base64-encode the public key file for use with --from / Kubernetes configuration
$ base64 -w0 startxxytwan7gfm6ojs6d2auwhwjhysjz3c5j2hd7grlokzmd4reoqd.onion/hs_ed25519_public_key
PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAACUwRne+J2A35is85MvD0Clj2SfEk52LqdHH80VuVlg+Q==
```

Edit `demo-k8s.yaml` to configure the prefix, starting public key, parallelism, and resource limits.

```console
$ # Create search job
$ kubectl apply -f demo-k8s.yaml
job.batch/ova created

$ # Check the job
$ kubectl get job ova
NAME   STATUS    COMPLETIONS   DURATION   AGE
ova    Running   0/999999      5s         5s

$ # Check pods
$ kubectl get pods --selector=batch.kubernetes.io/job-name=ova
NAME          READY   STATUS    RESTARTS   AGE
ova-0-tz27j   1/1     Running   0          7s
ova-1-zwlhl   1/1     Running   0          7s
ova-2-khl7f   1/1     Running   0          7s
ova-3-9l4z5   1/1     Running   0          7s
ova-4-tbx2m   1/1     Running   0          7s
ova-5-mpsz8   1/1     Running   0          7s
ova-6-xg7ft   1/1     Running   0          7s
ova-7-6zcn8   1/1     Running   0          7s
ova-8-cqrtj   1/1     Running   0          7s
ova-9-dtqhc   1/1     Running   0          7s

$ # Check resource usage
$ kubectl top pods --selector=batch.kubernetes.io/job-name=ova

$ # Wait for the job to complete
$ kubectl wait --for=condition=complete job/ova --timeout=1h
job.batch/ova condition met

$ # Job is complete
$ kubectl get job ova
NAME   STATUS     COMPLETIONS   DURATION   AGE
ova    Complete   1/999999      23m14s     23m44s

$ # Get found offset from the logs
$ kubectl logs jobs/ova
Found lukovitsa... lukovitsa6jy7sldxvdw7wwzdmf5sezbwgr5uf57kkhi3jep25g2d2id.onion (1/1) after 23m14s and 1.0T attempts (719.8M attempts/s)
---
hostname: lukovitsa6jy7sldxvdw7wwzdmf5sezbwgr5uf57kkhi3jep25g2d2id.onion
offset: sgowAsMLwBk=

$ # Locally generate the vanity keypair by offsetting the starting secret key
$ base64 -w0 startxxytwan7gfm6ojs6d2auwhwjhysjz3c5j2hd7grlokzmd4reoqd.onion/hs_ed25519_secret_key \
  | onion-vanity-address --offset=sgowAsMLwBk=
Wrote Tor service files to lukovitsa6jy7sldxvdw7wwzdmf5sezbwgr5uf57kkhi3jep27gzjlid.onion/

$ # Or write the offset result in Start9 format
$ base64 -w0 startxxytwan7gfm6ojs6d2auwhwjhysjz3c5j2hd7grlokzmd4reoqd.onion/hs_ed25519_secret_key \
  | onion-vanity-address --start9 --offset=sgowAsMLwBk=
Wrote Start9 key to lukovitsa6jy7sldxvdw7wwzdmf5sezbwgr5uf57kkhi3jep27gzjlid.onion

$ # Delete the job
$ kubectl delete job ova
job.batch "ova" deleted
```

## Similar tools

* [mkp224o](https://github.com/cathugger/mkp224o)
* [oniongen-go](https://github.com/rdkr/oniongen-go)

## The fastest search algorithm

Tor Onion Service [address](https://github.com/torproject/torspec/blob/main/rend-spec-v3.txt) is derived from ed25519 public key.

The tool generates candidate public keys until it finds one that has a specified prefix when encoded as onion address.

ed25519 keypair consists of:

* 32-byte secret key (scalar) - a random value that serves as the secret
* 32-byte public key (point) - derived by scalar multiplication of the base point by the scalar

ed25519 public key is a 32-byte y-coordinate of a point on a [Twisted Edwards curve](https://datatracker.ietf.org/doc/html/rfc8032) equivalent to [Curve25519](https://datatracker.ietf.org/doc/html/rfc7748#section-4.1).

Both `mkp224o` and `onion-vanity-address` leverage additive properties of elliptic curves to avoid full scalar multiplication for each candidate key.

Addition of points requires an expensive field inversion operation and both tools utilise batch field inversion, also known as the Montgomery trick, to perform a single field inversion per batch of candidate points.

The key performance difference is that while `mkp224o` uses point arithmetic that calculates both coordinates for each candidate point, `onion-vanity-address` uses curve coordinate symmetry and calculates only y-coordinates to reduce the number of field operations.

The algorithm has amortised cost **5M + 2A** per candidate key, where M is field multiplication and A is field addition.

See also:

* [vanity25519](https://github.com/AlexanderYastrebov/vanity25519) — Efficient Curve25519 vanity key generator.
* [wireguard-vanity-key](https://github.com/AlexanderYastrebov/wireguard-vanity-key) — Fast WireGuard vanity key generator.
* [age-vanity-keygen](https://github.com/AlexanderYastrebov/age-vanity-keygen) — Fast vanity age X25519 identity generator.
