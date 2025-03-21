# @openfn/language-fhir-ndr-et

## 0.1.11

### Patch Changes

- Updated dependencies [23ccb01]
  - @openfn/language-common@2.3.1

## 0.1.10

### Patch Changes

- Updated dependencies [b3d7f59]
- Updated dependencies [2d709ff]
- Updated dependencies [41e8cc3]
  - @openfn/language-common@2.3.0

## 0.1.9

### Patch Changes

- Updated dependencies [6dffdbd]
  - @openfn/language-common@2.2.1

## 0.1.8

### Patch Changes

- Updated dependencies [a47d8d5]
- Updated dependencies [9240428]
  - @openfn/language-common@2.2.0

## 0.1.7

### Patch Changes

- Fix typescript definitions

## 0.1.6

- Updated docs for each()
- Updated dependencies
  - @openfn/language-common@2.1.1
  - @openfn/language-fhir@5.0.3

## 0.1.5

### Patch Changes

- Order the generated code alphabetically

## 0.1.4

### Patch Changes

- 47bf58f: Adjust build process to fix docs

## 0.1.3

### Patch Changes

- Updated dependencies [03a1a74]
  - @openfn/language-common@2.1.0

## 0.1.2

### Patch Changes

- Fixed security vulnerability in jsonpath-plus [33973a2]
  - @openfn/language-common@2.0.3

## 0.1.1

### Patch Changes

- Update spec version

## 0.1.0

Initial release

## 0..19

- Map text values into "code"

## 0.0.18

- Make composite types smarter when passed a Resource (convert it to a
  reference)

## 0.0.17

- support more types in addExtension

## 0.0.16

- Add `text` to each resource type

## 0.0.15

- Update schema to lateest version

## 0.0.14

- add relatedPerson builder

## 0.0.13

- reference will generate a reference to a resource if you pass it in (in form
  type/id)
- add aliases for util.ref, util.id, util.cc
- properly track arrays of references

## 0.0.12

- Make util.findExtension safe for resources without an extension

## 0.0.11

- Add builders for MedicationDispense and Medication
- Tighten extension mapping

## 0.0.10

- Improvements to observation (map references, default static values, and handle
  value)

## 0.0.9

- Fix prop mapping which arent in an array util.
- concept accepts codings as anarray allow systems map to map system shorthands
  and longhands to new values
- Fix utils namespace

## 0.0.8

Ignore nullish keys in mapping (ie, passing undefined will not set a key on the
new object)

## 0.0.7

- restore all builders
- more docs in type defs

## 0.0.6

- Support more types
- remove generic property mapping - most props should map now

## 0.0.5

- restore patient and observation types
- hide internal builder functions

## 0.0.4

add type variants add flat assignment of props to resource

## 0.0.3

expose more stuff from common

## 0.0.2

expose fn

## 0.0.1

Initial alpha release.
