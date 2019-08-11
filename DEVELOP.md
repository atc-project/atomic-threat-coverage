The code for Atomic Threat Coverage is hosted on GitHub. [Pull requests](https://help.github.com/articles/about-pull-requests/) are welcome, for both code or documentation. You may also report an issue or bug [here](https://github.com/atomic-threat-coverage/atomic-threat-coverage/issues).

If you don't feel confident in your Git and/or Python skills, you can get up-to-speed with [these tutorials](http://matthew-brett.github.com/pydagogue/). If you would like to share an idea for improvement you can create [issue](https://github.com/atomic-threat-coverage/atomic-threat-coverage/issues) or contact us in [Slack](https://join.slack.com/t/atomicthreatcoverage/shared_invite/enQtNTMwNDUyMjY2MTE5LTk1ZTY4NTBhYjFjNjhmN2E3OTMwYzc4MTEyNTVlMTVjMDZmMDg2OWYzMWRhMmViMjM5YmM1MjhkOWFmYjE5MjA) or [Telegram](https://t.me/atomic_threat_coverage) to discuss it.

# Documentation

Python docstrings are for an overview of the functionality, to anchor a class or method conceptually and check their parameters, **do not** to describe how things work internally in detail. For all other cases, the code have to be its own documentation. Any non-obvious tricks and coding patterns that may confuse an otherwise literate Python programmer need a source code comment.

**ATC is in permanent need of better tutorials, usage examples, as well as clearer docstrings. Contributions are most welcome.**

# Git flow

Branching model follows [this](http://nvie.com/posts/a-successful-git-branching-model/) document: 

- `master` branch is stable, HEAD is always the latest release
- `develop` branch contains the latest code for the next release
- various feature branches, to be merged into `develop` upon completion
- include the issue number in the name of the branch

For a new feature, branch off `develop`:

```sh
$ git checkout -b myfeature develop
```

To merge a feature back into `develop`:

```sh
$ git checkout develop
$ git merge --no-ff myfeature
$ git branch -d myfeature
$ git push --tags origin develop
```

# Code style

[PEP8](https://www.python.org/dev/peps/pep-0008/) in common: no trailing whitespace in the source code, whitespace on empty Python lines (lines separating blocks of code/methods etc.) and so on. No vertical indents (only hanging indents).

# Making a new release

Check that all CI in ATC repository passed correctly for last commit in 'develop`.

To start a new release, first, branch off `develop`:

```sh
export RELEASE=X.Y.Z
git checkout -b release-${RELEASE} develop
```

where `X.Y.Z` corresponds to `major.minor.patch`:

- Major version numbers change whenever there is some significant change being introduced. For example, a large or potentially backward-incompatible change to a software package
- Minor version numbers change when a new, minor feature is introduced or when a set of smaller features is rolled out
- Patch numbers change when a new build of the software is released to customers. This is normally for small bug-fixes or the like

**What does that mean?**  

- If you are introducing **bug-fix** or something like this - you should increment Z by one. So **new version should be** X.Y.(Z+1)

- If you are introducing new **small feature** - you should increment Y by one and set Z to 0, so **new version should be** X.(Y+1).0

- And if you are introducing new **major release** - you shoud increment X by one and set Y and Z to 0 so **new version should be** (X+1).0.0

```sh
git commit -m "bump version to ${RELEASE}"
```

Also, **don't forget to update `CHANGELOG.md`**

```sh
git add CHANGELOG.md
git commit -m "bump CHANGELOG to ${RELEASE}"
```

Merge the branch into `master`, tag and merge `master` to `develop`:

```sh
git checkout master
git merge --no-ff release-${RELEASE}
git tag -a ${RELEASE} -m "${RELEASE}"
git push --tags origin master
git checkout develop
git merge --no-ff master
git push origin develop
```

Add text description in [Tags](https://github.com/atomic-threat-coverage/atomic-threat-coverage/tags).
