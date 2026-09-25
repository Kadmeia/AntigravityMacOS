# Third-party notices

Antigravity Unlocker is distributed under GNU GPL-3.0. The complete license is
in `LICENSE`; upstream attribution and modification notices are in `NOTICE.md`.
The build also contains components owned by their respective authors.

| Component | Version used for release | License |
|---|---:|---|
| CPython | 3.11.x | Python Software Foundation License |
| pywebview | 6.2.1 | BSD-3-Clause |
| PyObjC core, Cocoa and WebKit bindings | 11.1 | MIT |
| bottle | 0.13.4 | MIT |
| proxy_tools | 0.1.0 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| PyInstaller bootloader/runtime | 6.22.2 | GPL-2.0-or-later with the PyInstaller Bootloader Exception; some runtime hooks use permissive licenses |

Exact dependency license files available in the build environment are copied to
`third_party_licenses/` inside the application and disk image. Versions should
be regenerated and reviewed whenever dependencies change.

## pywebview — BSD 3-Clause License

Copyright (c) 2014-2017, Roman Sirokov. All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## MIT-licensed components

PyObjC, bottle, proxy_tools, altgraph and macholib use the MIT License. Their
individual copyright notices and license files are included in
`third_party_licenses/` in the release image.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the “Software”), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to inclusion of the applicable copyright and permission notices.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## PyInstaller and Python

PyInstaller is licensed under GPL-2.0-or-later with a special exception that
permits distribution of applications produced with its bootloader. The exact
PyInstaller license and exception from the installed release are included with
the distribution. CPython is distributed under the Python Software Foundation
License; its license notice is included with the embedded runtime where supplied
by the Python distribution.
