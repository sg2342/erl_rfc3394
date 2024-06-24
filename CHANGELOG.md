# Changelog

## 1.0.1 (2024-06-24)

  * Bug fixes
	  * Fix `rfc3394:wrap/3` guard (minimal `byte_size/1` of `KeyData` is 8)
	  * Fix `rfc3394:unwrap/3` guard (minimal `byte_size/1` of `Cipertext` is 16)

  * Enhancements
	  * Introduce types and size constraints for `kek()`, `iv()`, `keyData()` and `cipertext()`
	  * Improve function documentation strings

## 1.0.0 (2024-06-19)

  * First public release
