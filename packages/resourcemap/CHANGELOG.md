# @openfn/language-resourcemap

## 0.4.12

### Patch Changes

- Updated dependencies [23ccb01]
  - @openfn/language-common@2.3.1

## 0.4.11

### Patch Changes

- 8a8c28d: - cleanup examples wrapped with `execute()` function
  - Add example caption and add sample payload

## 0.4.10

### Patch Changes

- Updated dependencies [b3d7f59]
- Updated dependencies [2d709ff]
- Updated dependencies [41e8cc3]
  - @openfn/language-common@2.3.0

## 0.4.9

### Patch Changes

- Updated dependencies [6dffdbd]
  - @openfn/language-common@2.2.1

## 0.4.8

### Patch Changes

- Updated dependencies [a47d8d5]
- Updated dependencies [9240428]
  - @openfn/language-common@2.2.0

## 0.4.7

### Patch Changes

- Updated docs for each()
- Updated dependencies
  - @openfn/language-common@2.1.1

## 0.4.6

### Patch Changes

- Updated dependencies [03a1a74]
  - @openfn/language-common@2.1.0

## 0.4.5

### Patch Changes

- Fixed security vulnerability in jsonpath-plus [33973a2]
  - @openfn/language-common@2.0.3

## 0.4.4

### Patch Changes

- 8d866e4: Update tough-cookie dependency

## 0.4.3

### Patch Changes

- Updated dependencies [77a690f]
  - @openfn/language-common@2.0.2

## 0.4.2

### Patch Changes

- 8146c23: Fix typings in package.json
- Updated dependencies [8146c23]
  - @openfn/language-common@2.0.1

## 0.4.1

### Patch Changes

- Updated dependencies [4fe527c]
  - @openfn/language-common@2.0.0

## 0.4.0

### Minor Changes

- 73433c20: Add `fnIf` operation

### Patch Changes

- Updated dependencies [106ecf6d]
  - @openfn/language-common@1.14.0

## 0.3.2

### Patch Changes

- 6afba70: Fix submitSite

## 0.3.1

### Patch Changes

- Update lock files
- Updated dependencies
  - @openfn/language-common@1.8.1

## 0.3.0

### Minor Changes

- 2c1d603: Remove parameter reassignment to ensure proper functioning inside an
  `each` block; add eslint

  The packages receiving a major bump here exposed functions that didn't work as
  expected inside `each` blocks. Users were previously wrapping these functions
  inside their own custom `fn` blocks, and this change will ensure that they can
  be used inside a standard each.

  See https://github.com/OpenFn/adaptors/issues/275 for more details.

### Patch Changes

- Updated dependencies [2c1d603]
  - @openfn/language-common@1.8.0

## 0.2.3

### Patch Changes

- 14f481e: mark execute as private
- Updated dependencies [2b4c61a]
  - @openfn/language-common@1.7.6

## 0.2.2

### Patch Changes

- f7ebd3c: remove sample configuration

## 0.2.1

### Patch Changes

- f2aed32: add examples

## 0.2.0

### Minor Changes

- 664dc7f: migrate resourcemap
