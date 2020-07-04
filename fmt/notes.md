# z3

A theorem prover by microsoft (duh?)

# z3 usage


### `BitVec`

This will initialize the array with of the amount of constraints that needs to be be met.

### `Solver`

`Solver` implements a class which can be later used to add constraints that needs to be proven.

### `add`

This is to add constraints, the variables that had to be proven.

### `check`

This return if the `Solver` is successful or not. If it's successful, it will return `sat` otherwise `unsat`.

### `model`

This is will return a resultant array if thw `check` is `sat` with of the constrainst whoch fulfilled the conditions.
