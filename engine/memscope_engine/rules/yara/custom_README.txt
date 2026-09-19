Place .yar / .yara files here. Dumplyzer never overwrites this folder.

  memory\    Rules used when scanning the original memory dump
  artifact\  Rules used when scanning extracted PE / artifacts
  *.yar      Files in this folder root are used for both scan types

Optional meta.severity (info, low, medium, high, critical) is shown as Level
on the Signatures results table. meta.level is accepted as an alias.

Invalid files are skipped (with an error) and are not deleted.
