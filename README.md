# High P-Code Viewer
This is a Ghidra plugin that adds a window showing the high P-code for the current function; when a pseudo-C statement is clicked on in the Decompile window, the corresponding high P-code is highlighted and scrolled into focus:

![HighPCodeViewer](https://user-images.githubusercontent.com/77587819/224444631-112f70f1-544e-416c-89c9-13257e11ab53.gif)

## What is high P-code and why can it be useful?

High P-code is Ghidra's final intermediate representation of the decompiled binary, coming after data and control flow analysis and before the generation of pseudo-C code:

![image](https://user-images.githubusercontent.com/77587819/224443557-d52d18f4-2f09-4beb-8928-72e4d6fad615.png)

As such, it is the highest level at which pattern detection can conveniently be performed programmatically and therefore well suited for scripting detection of patterns in decompiler output. For a more in-depth explanation and illustration, read [this article](https://twevs.github.io/2023/03/10/using-high-p-code-to-detect-patterns-in-decompiler-output.html).

## Installation

1. Download the release targeting your version of Ghidra.
2. In the main Ghidra window (not the CodeBrowser), click on `File > Install Extensions...`, then `Add extension`, and select the downloaded ZIP file.
3. If, after restarting, you do not see `High P-Code Viewer` in the CodeBrowser's `Window` menu, click on `File > Configure... > [Miscellaneous] Configure` and make sure `HighPCodeViewerPlugin` is enabled.

Once displayed, the viewer can be docked with the console for greater convenience.

## Building

1. In Eclipse, install the GhidraDev extension from `[Ghidra root folder]/Extensions/Eclipse/GhidraDev`. This will add a `GhidraDev` element to the menu bar.
2. Add your Ghidra root folder to `GhidraDev > Preferences > Ghidra Installations...`.
3. Clone this repository and import it via `File > Import... > Existing Projects into Workspace`.
4. Right-click on the project name and in the context menu, click on `GhidraDev > Link Ghidra...`; the `Run As...` and `Debug As...` options should now enable you to launch Ghidra with the built plugin. (Note that a conflict is possible if you have already installed it from within Ghidra.)
5. You can export the plugin using the aforementioned context menu, via `GhidraDev > Export > Ghidra Module Extension...`.
