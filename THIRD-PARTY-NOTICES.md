# Third-party notices

Guard Dog's website ships everything it needs inside this repository. It loads nothing from outside servers. These are the third-party files it includes:

| Component | Version | Files | License |
|---|---|---|---|
| [GSAP](https://gsap.com) (animation) | 3.12.5 | `docs/vendor/gsap/gsap.min.js` | GSAP Standard License, free for everyone including commercial use. Full text: [`docs/vendor/gsap/LICENSE`](docs/vendor/gsap/LICENSE) |
| [Inter](https://github.com/rsms/inter) (typeface), Latin subset | 4.x (Fontsource build) | `docs/vendor/fonts/inter-latin-{300,400,500,600,700}-normal.woff2` | SIL Open Font License 1.1. Full text: [`docs/vendor/fonts/LICENSE`](docs/vendor/fonts/LICENSE) |

## SHA-256 of the included files

```text
28033e449a31ebcc396e5be8b13b63152bf03094288fb5867034321927bce087  docs/vendor/gsap/gsap.min.js
09eea703e2e860332003283cd9b21cabe959a765e0f5571e0bafbe22f2423c56  docs/vendor/fonts/inter-latin-300-normal.woff2
2301bb030a2bcaa9c763cc4771bd717aac16709c29eaba00673fcbe7cdf99a59  docs/vendor/fonts/inter-latin-400-normal.woff2
eebf14aba456b89b7e899584e076588a92e422a45b37fb5fa36ce17519a3e8c5  docs/vendor/fonts/inter-latin-500-normal.woff2
3022fadde78fd30c384797bcef8bebc18c96083527a850f62a58d8957a8b208f  docs/vendor/fonts/inter-latin-600-normal.woff2
7b43cb86a0e63bbb55376b4ea60d8cc9527a1421c367aa09962725e0c5140f5f  docs/vendor/fonts/inter-latin-700-normal.woff2
```

Check them with `shasum -a 256 -c` against the list above.
