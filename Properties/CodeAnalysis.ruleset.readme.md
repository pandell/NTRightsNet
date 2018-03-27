This rules file was based on `(Visual Studio 2017 install path)\Team Tools\Static Analysis Tools\Rule Sets\MinimumRecommendedRules.ruleset`

- Disables rule "IDE0001": _Simplify Names_ (Rely on R# naming rules)

- Disables rule "IDE0002": _Simplify Member Access_ (IDE will not suggest removing `MyClass` from `MyClass.StaticMember`)

- Disables rule "IDE0003": _Remove 'this' or 'Me' qualification_ (IDE will not suggest removing `this` from `this.Member`)

- Disables rule "IDE0004": _Remove Unnecessary Cast_ (Rely on R# suggestions)

- Disables rule "IDE0005": _Using directive is unnecessary_ (Rely on R# cleanup)

- Disables rule "IDE1005": _Delegate invocation can be simplified_ (Rely on R# suggestions)
