# How to submit an issue?

First, please see [contribution-guide.org](http://www.contribution-guide.org/) for the steps we expect from contributors before submitting an issue or bug report. Be as concrete as possible, include relevant logs, package versions etc.

Also, please check [FAQ](https://gitlab.com/krakow2600/atomic-threat-coverage/wikis/FAQ) 

<b> The proper place for open-ended questions is <a href="https://join.slack.com/t/atomicthreatcoverage/shared_invite/enQtNTMwNDUyMjY2MTE5LTk1ZTY4NTBhYjFjNjhmN2E3OTMwYzc4MTEyNTVlMTVjMDZmMDg2OWYzMWRhMmViMjM5YmM1MjhkOWFmYjE5MjA"> Slack</a> or <a href="https://t.me/atomic_threat_coverage">Telegram</a> </b> Github is not the right place for research discussions or feature requests.

# How to add a new feature or create a pull request?

1. <a href="https://gitlab.com/krakow2600/atomic-threat-coverage/forks/new">Fork the ATC repository</a>
2. Clone your fork: `git clone git clone https://gitlab.com/<YOUR GITLAB USERNAME>/atomic-threat-coverage.git`
3. Create a new branch based on `develop`: `git checkout -b my-feature develop`
4. Setup your Python enviroment
   - Create a new [virtual environment](https://virtualenv.pypa.io/en/stable/): `pip install virtualenv; virtualenv atc_env` and activate it:
      - For linux: `source atc_env/bin/activate` 
      - For windows: `atc_env\Scripts\activate`
   - Install ATC and its test dependencies in [editable mode](https://pip.pypa.io/en/stable/reference/pip_install/#editable-installs): 
      - For linux: `pip install -r requirements.txt`
      - For windows: `pip install -r requirements.txt`
5. Implement your changes
6. Check that everything's OK in your branch:
   - Check it for PEP8: 
7. Add files, commit and push: `git add ... ; git commit -m "my commit message"; git push origin my-feature`
8. [Create a PR](https://help.github.com/articles/creating-a-pull-request/) on Github. Write a **clear description** for your PR, including all the context and relevant information, such as:
   - The issue that you fixed, e.g. `Fixes #123`
   - Motivation: why did you create this PR? What functionality did you set out to improve? What was the problem + an overview of how you fixed it? Whom does it affect and how should people use it?
   - Any other useful information: links to other related Github or mailing list issues and discussions, benchmark graphs, academic papers…

P.S. for developers: see our [Developer Page](https://gitlab.com/krakow2600/atomic-threat-coverage/wikis/Developer-guide) for details on the code style, CI, testing and similar.

**Thanks and let's improve the open source world together!**