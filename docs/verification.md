# Local verification

18 November 2026, macOS arm64, Python 3.12. Nine standard-library unit tests passed.

`python3 -m unittest discover -s tests -v`

The tests cover the illustrative model, volume scaling, valid zero retention, invalid event size, negative volume, invalid peak, non-finite inputs, negative retention, and invalid replica counts. They check arithmetic and input validation. No cloud, network, isolated-site recovery, signature, legal, or sovereignty assurance was tested.

The arithmetic reference derives from Ashish Srivastava's existing generic capacity-model work. This public edition adds explicit input validation and negative cases.
