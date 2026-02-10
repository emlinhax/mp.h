# example usage

```cpp
char buf[] = (...)
int status = defender::boot("C:\\mpengine", "*.*");
auto scan_result = defender::scan_buffer(buf, sizeof(buf));
printf("%s\n", scan_result.second->identifier);

// output
> "Trojan:PowerShell/RevShellz.ZZ!MTB"
```

# setup
put mpengine.dll and all .vdm files into the same folder as the one you specify at engine boot. \
thats really it. you can use the "everything" tool to find .vdm / mpengine.dll if you cant find it manually.

# credits
https://github.com/0xAlexei/WindowsDefenderTools \
https://github.com/ig-labs/defender-mpengine-fuzzing
