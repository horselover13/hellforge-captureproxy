# hellforge-capture-proxy

An ""AI-assisted"" standalone rewrite of [HellForge.CaptureProxy](https://github.com/SkyeShade/HellForge/tree/main/src/HellForge.CaptureProxy), made to work with Linux.

## Capturing

HellForge runs its own CaptureProxy with those arguments:

```
--output <install>/logs/sync-<timestamp>/real-inventory.json
--progression <install>/logs/sync-<timestamp>/progression.json
--evidence <install>/logs/sync-<timestamp>
--seal-key <install>/account-snapshot/seal.key 
--steam-account <STEAM ACCOUNT ID>
```

In this case, we don't *have to* use the staging folder `<install>/logs/sync-<timestamp>`, since this is a standalone version. It's still recommended you make *some kind of* staging folder.

Steam account ID can be obtained by just copying your steam account link. That big number is your ID.

`<install>/account-snapshot` is the final destination for account data. You may still keep `seal.key` in your staging folder, in the meantime.

Roughly, your hellforge-capture-proxy command should look like:

```
mkdir -p staging/
sudo ./hellforge-capture-proxy \
  --output ./staging/real-inventory.json \
  --progression ./staging/progression.json \
  --evidence ./staging/ \
  --seal-key ./staging/seal.key \
  --steam-account <YOUR STEAM ACCOUNT ID>
```

Now, start the game. Capture Proxy will automatically violently die when the game closes. When you reach the title screen, and walk around super destroyer for a bit, you can close the game.

This produces roughly 6 files:

- `real-inventory.json` & `progression.json` - the thing you are here for, progression and inventory data fetched from the game
- `proxy.log` & `capture-state.json` - seem to be logging files, in case if capture explodes
- `seal.json` & `seal.key` - unique keys attached to your steam account, your progression and inventory data files, and your MAC address. (read: literally ID of your hardware) used by hellforge to make sure you aren't sinning on their behalf.

## Forcing HF to eat it up

HellForge stores its account data in `<install>/account-snapshot/<profile>`

`seal.key` is the odd one out from those files - its a key *per installation*, instead of per profile. Therefore, you throw it into `<install>/account-snapshot` instead.

As for everything else:

```
<install>/account-snapshot/<profile>/
├── real-inventory.json
├── progression.json
├── seal.json
└── snapshot.json
```

`snapshot.json` is the metadata, and is not provided by the main program. Instead, we must generate it with a script:

```
python3 manifest_generator.py staging/
```

That should spit out `snapshot.json` into the `staging/` folder.
