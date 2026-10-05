if (args.Length < 2)
    throw new ArgumentException("Usage: Reference metadata.blob output.json | r2r output.jsonl paths...");
if (args[0] == "r2r") ReadyToRunReference.Export(args[1], args.Skip(2));
else NativeFormatReference.Export(args[0], args[1]);
