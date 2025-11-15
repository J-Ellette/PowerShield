# Quick README.md Fixes for Marketplace Release

Based on the linting errors detected, here are the minor fixes needed:

## 1. Remove HTML `<br>` Tags

Replace lines 5-6:

```markdown
![Version](https://img.shields.io/badge/version-1.8.0-blue) <br>
[![PowerShield - PowerShell Security Analysis](https://github.com/J-Ellette/PowerShellTestingSuite/actions/workflows/powershell-security.yml/badge.svg)](https://github.com/J-Ellette/PowerShellTestingSuite/actions/workflows/powershell-security.yml) <br>
```

With:

```markdown
![Version](https://img.shields.io/badge/version-1.8.0-blue)
[![PowerShield - PowerShell Security Analysis](https://github.com/J-Ellette/PowerShellTestingSuite/actions/workflows/powershell-security.yml/badge.svg)](https://github.com/J-Ellette/PowerShellTestingSuite/actions/workflows/powershell-security.yml)
```

## 2. Fix List Formatting

Add blank lines before and after list sections (around lines 24, 63, 100, etc.)

## 3. Remove Trailing Spaces

Clean up trailing spaces on lines ending with `:` characters

## 4. Fix Heading Spacing

Add blank lines before section headings (around lines 382, 424, 651, etc.)

## 5. Add Language to Code Blocks

Specify language for the empty code block around line 742

These are all cosmetic formatting issues that don't affect functionality.
