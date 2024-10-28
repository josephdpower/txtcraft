# txtcraft

```
_______   _______     .___________.___   ___ .___________.  ______ .______          ___       _______ .___________.
|       \ |       \    |           |\  \ /  / |           | /      ||   _  \        /   \     |   ____||           |
|  .--.  ||  .--.  |   `---|  |----` \  V  /  `---|  |----`|  ,----'|  |_)  |      /  ^  \    |  |__   `---|  |----`
|  |  |  ||  |  |  |       |  |       >   <       |  |     |  |     |      /      /  /_\  \   |   __|      |  |     
|  '--'  ||  '--'  |       |  |      /  .  \      |  |     |  `----.|  |\  \----./  _____  \  |  |         |  |     
|_______/ |_______/        |__|     /__/ \__\     |__|      \______|| _| `._____/__/     \__\ |__|         |__|
```
## Usage

This tool formats files that contain indicators-of-compromise

e.g.

```
www[.]thisdomainisbad[.]com
hxxps[://]hackerman[.]dev
127[.]0[.]0[.]1
192[.]168[.]0[.]1
```

Depending on the controls required, the program takes command-line arguments and (depending), offers the user a change to add comments
when appropiate.

E.g., if I wanted to put a malicious domain into the whitelist, the output may look like:

```
*.thisdomainisbad.com   TXT "Class: Malicious, josephdpower, 01012002"
*.thisdomainisbad.com   A   127.0.0.1
```

URLs that begin with "www." are wildcarded with the "*." expression.
