# Service accounts

This is the documentation for working with Youwol service accounts development, building and deployment.

* [Git submodule `./py-youwol`](#git-submodule-py-youwolpy-youwol)
  * [In a nutshell](#in-a-nutshell)
  * [Cloning & Initializing](#cloning--initializing)
  * [Updating the submodule](#updating-the-submodule)
  * [Synchronizing submodule with another remote](#synchronizing-submodule-with-another-remote-ie-a-local-repository-not-pushed)
* [Docker image](#docker-image)
  * [Building with `Dockerfile`](#building-with-dockerfiledockerfile)
  * [Naming & Tagging](#naming--tagging)
* [Helm chart](#helm-chart)
  * [Managing dependencies](#managing-dependencies)
  * [Updating for new app version](#updating-for-new-app-version)
  * [Customizing](#customizing)
  * [Deploying](#deploying)

*All commands are run from this repository root directory.*

## Git submodule [`./py-youwol`](./py-youwol)

This project use a submodule in [`./py-youwol` directory](./py-youwol) to track
[py-youwol](https://github.com/youwol/py-youwol) code.

A **submodule** allow a **super-project** to track another git repository : the git history of the **super-project**
only record the commit of the **submodule**, and the working directory of the super-project has a working directory
where this commit is checked out.

For this project :

* the **super-project** is this repository itself
* the **submodule** track [py-youwol](https://github.com/youwol/py-youwol)
* the **submodule** is check out in [`py-youwol` directory](./py-youwol)

### In a nutshell

Here are the basic commands for working with `git submodule`. Be sure to read the other sections for detailed
information.

* [Some useful configurations](#some-useful-configurations)
* [After cloning or pulling this project](#after-cloning-or-pulling-this-project)
* [Updating py-youwol to remote](#updating-py-youwol-to-remote)
* [Inside the submodule working dir](#inside-submodule-working-dir)
* [Getting local py-youwol changes](#get-local-py-youwol-repository-changes)
* [Pitfalls](#pitfalls)

#### Some useful configurations

```shell
$ git config push.recurseSubmodules check      # prevent pushing submodule commit if it is not in its remote
$ git config status.submodulesummary yes       # show summary in git status when submodule has changes 
$ git config diff.submodule log                # show log in git diff when submodule has changes
$ git config submodule.py-youwol.udpate rebase # rebase submodule local commits when using git submodule update --remote
```

#### After cloning or pulling this project

Run this command after each pull of **super-project** :

```shell
$ git submodule update --init ./py-youwol      # will check out recorded commit detached, initializing if necessary
```

#### Updating py-youwol to remote

Run this command to update submodule to the latest changes :

```shell
$ git submodule update --remote ./py-youwol                  # will fetch & check out origin/master detached
```

#### Inside submodule working dir

Inside [`py-youwol` directory](./py-youwol) git works as usual.

```shell
$ git submodule update --init ./py-youwol                    # check out recorded commit detached
$ git -C ./py-youwol status                                  # HEAD detached
$ git -C ./py-youwol checkout master                         # branch master now track origin/master
$ echo "foo" > ./py-youwol/test
$ git -C ./py-youwol add ./test
$ git -C ./py-youwol commit -m "New py-youwol commit"
$ git -C ./py-youwol fetch && git -C py-youwol rebase
$ git -C ./py-youwol push                                    # Ensure others can fetch recorded commit
$ git status                                                 # show new commits in ./py-youwol
$ git add ./py-youwol           
$ git commit -m "Updated py-youwol"                          # record submodule commit in super-project history
$ git fetch && git rebase
$ git push
```

*the `-C` option instruct `git` subcommands to run inside `./py-youwol*

#### Get local py-youwol repository changes

Assuming there is a local copy of [py-youwol](https://github.com/youwol/py-youwol) at `/path/to/local/py-youwol`
with a local branch `local_branch`, the following commands will check out this branch into the submodule working
directory :

```shell
$ git -C py-youwol remote add local file:///path/to/local/py-youwol
$ git -C py-youwol fetch local
$ git -C py-youwol checkout local_branch
$ git status                                     # show new commits in ./py-youwol if local_branch ≠ origin/master
```

**Be sure to push `local_branch` to [py-youwol](https://github.com/youwol/py-youwol) before pushing the super-project
changes.**

#### Pitfalls

- `git submodule` subcommands always check out commits detached.
- Always run `git submodule update py-youwol` after pulling from super-project repository.
- Be sure to push any **submodule** commits to [py-youwol](https://github.com/youwol/py-youwol) before pushing
  **super-project**.

### Cloning & Initializing

`git clone` does not check out the submodule into its directory, unless using the following command line argument :

```shell
$ git clone --recursive https://github.com/youwol/accounts
```

If the project has already been cloned, or after pulling new entries in
[submodule configuration in `.gitmodules`](./.gitmodules), the submodule must be (re)initialized with the following
command (see below for a better alternative) :

```shell
$ git submodule init ./py-youwol                   # initialize submodule
```

After pulling changes moving the commit of the submodule, the working directory must be updated with the following
command (see below for a better alternative):

```shell
$ git submodule update ./py-youwol                 # check out recorded commit detached
```

However, it can be cumbersome to manually check each pull for these changes, so it’s best to use the following
command after each pull :

```shell
$ git submodule update --init ./py-youwol          # will check out recorded commit detached, initializing if necessary
```

With all these commands, the submodule working directory will check out HEAD detached.

### Updating the submodule

* [Using git inside the submodule](#using-git-inside-the-submodule-working-directory)
* [Using `git submodule update`](#using-git-submodule-update-in-super-project-working-directory)

#### Using git inside the submodule working directory

The submodule directory is a regular git repository, so most git commands will work as expected in that directory.
Since the working directory is in detached HEAD, the first thing to do is to check out master :

```shell
$ git -C ./py-ywoul checkout master && git status
```

*the `-C` option instruct `git` subcommands to run inside `./py-youwol*

If the super-project is not clean after these commands, it’s mean that master on
[py-youwol](https://github.com/youwol/py-youwol) has moved forward since the last super-project commit.

Once a branch is check out, git will work as usual inside the submodule working directory.
There is however some caveats :

* dirty work will not be recorded in super-project history, since only submodule HEAD commit is recorded.
* recorded submodule commit must be in remote for other to actually get the code when cloning or pulling super-project.

#### Using `git submodule update` in super-project working directory

The --remote option of `git submodule update` allow submodule to be updated to the submodule remote :

```shell
$ git submodule update --remote              # will fetch origin & checkout origin/master detached
```

If there is a branch checked out in the submodule working directory, rebasing or merging can be done with this
command :

```shell
$ git submodule update --remote --rebase     # or --merge
```

Configuration key submodule.py-youwol.update can be set to rebase or merge instead of passing these options.

### Synchronizing submodule with another remote (i.e. a local repository not pushed)

It’s possible to change locally the submodule remote url (i.e. only for the local repository of the super project) :

```shell
$ git submodule update --init py-youwol                             # submodule must be initialized
$ git -C py-youwol remote set-url origin file:///path/to/py-youwol  # remote is now /path/to/py-youwol
$ git -C py-youwol status                                           # HEAD is still detached
$ git status                                                        # no change
$ git -C py-youwol checkout local_branch                            # local_branch will track /path/to/py-youwol
$ git status                                                        # submodule commit has changed
```

**Once again, the recorded submodule commit must be present in py-youwol remote before pushing super-project.**

## Docker image

This project is build into a docker image, which is published in
[Gitlab project repository](https://gitlab.com/youwol/platform/container_registry).
Docker image tag is used by [Helm chart](#helm-chart) to find image for deployment.

### Building with [`Dockerfile`](./Dockerfile)

The `Dockerfile` is at the [conventional place](./Dockerfile), so building is straightforward
(see also [`docker build` documentation](https://docs.docker.com/engine/reference/commandline/build/)):

```shell
$ docker build -t accounts .     # image will be tagged with "latest"
```

This will install all necessary python dependencies (with `pip install`) and copy project code into a docker image
named `accounts:latest`.

### Naming & Tagging

Docker image repository name should be based on the repository name and project name.
It shall be tagged with at least `latest` and the app version.
The following commands will tag and publish a version `0.0.6-wip`:

```shell
$ docker tag accounts:latest registry.gitlab.com/youwol/platform/accounts:latest
$ docker tag accounts:latest registry.gitlab.com/youwol/platform/accounts:0.0.6-wip
$ docker push registry.gitlab.com/youwol/platform/accounts:latest
$ docker push registry.gitlab.com/youwol/platform/accounts:0.0.6-wip
```

## Helm chart

The Helm chart of this project is lightweight, opinionated and simple : all templating is done by the chart dependency
lib-backend, and there is only a few values available for customization.

Chart files reside in [`./chart` directory](./chart) :

* `chart/Chart.yaml` hold chart version, app version and dependencies versions.
* `chart/values.yaml` hold customization values.
* `chart/templates/` hold the templates themselves.
* `chart/Chart.lock` pin dependencies version and should be maintained with `helm depency update`
* `chart/charts/` hold dependencies themselves. It shall be build out with `helm dependency build`

### Managing dependencies

Helm allow charts to specify dependency on other charts in the section
[`dependencies` in `chart/Chart.yaml`](./chart/Chart.yaml). These dependencies must be collected in `chart/charts`.
* [Building out `chart/charts`](#building-out-chartcharts)
 
  `helm dependency build` will collect dependencies pinned in `chart/Chart.lock`.

* [Upgrading lib-backend](#upgrading-lib-backend)

  This project chart depends on `lib-backend`, a custom chart library grouping common templating for Youwol deployment.
  `helm dependency update` maintain checksum and effective versions of denpendencies in `chart/Chart.lock`.

#### Building out `chart/charts`

Directory `chart/charts` is not versioned. It must be build out from `chart/Chart.lock` with the following command
(see also [`helm dependency build` documentation](https://helm.sh/docs/helm/helm_dependency_build/)) :

```shell
$ helm dependency build ./chart    # Will collect dependencies in chart/charts/
```

#### Upgrading `lib-backend`

The version of `lib-backend` is specified in section [`dependency` in `chart/Chart.yaml`](./chart/Chart.yaml).
After modifying this value, `chart/Chart.lock` must be updated by issuing the following command (see also
[`helm dependency update` documentation](https://helm.sh/docs/helm/helm_dependency_update/)):

```shell
$ helm dependency update ./chart  # update chart/Chart.lock and collect dependencies in chart/charts/
```

Value of [version in `chart/Chart.yaml`](./chart/Chart.yaml) shall be incremented after this change.

**There is no reason to modify the AppVersion when modifying the chart itself**

### Updating for new app version

Value of [appVersion in `chart/Chart.yaml`](./chart/Chart.yaml) will be used for the tag of the docker image deployed.

**There is no reason to modify the chart version itself when deploying a new image**

### Customizing

Customization is done by passing values on command line with `--set key=value`, by supplying a values file on
command line with `-f file.yaml` or by editing `chart/values.yaml`.
Any permanent change shall be done by modifying `chart/values.yaml` and committing this file.

Please refer to [`chart/values.yaml` comments](./chart/values.yaml) for available options.

### Deploying

Before deploying a new release, its manifest should be carefully reviewed (see also
[`helm lint` documentation](https://helm.sh/docs/helm/helm_lint/)) :

```shell
$ echo platformDomain=platform.example.com > /tmp/values.yaml                  # provide missing values when offline
$ helm lint -f /tmp/values.yaml accounts ./chart                               # Examine chart for possible issues
$ helm get manifest -f /tmp/values.yaml accounts charts > /tmp/current.yaml    # get current manifest 
$ helm template -f /tmp/values.yaml accounts ./chart > /tmp/next.yaml          # template the manifest
$ diff /tmp/current.yaml /tmp/next.yaml                                        # review differences
```
*NB: because these commands do not actually connect to the Kubernetes cluster, some values would be missing and must 
provide. See [`chart/values.yaml` comments](./chart/values.yaml).*

If everything looks fine, deployment can be done with the following commands :

```shell
$ kubectl config use-context prod:apps                                         # set kubectl for cluster & namespace
$ helm upgrade --install --dry-run -f /tmp/values.yaml accounts ./chart        # last sanity check − still offline
$ helm upgrade --install accounts ./chart                                      # Actual deployment
$ helm history accounts                                                        # review deployment history
```
*NB: output of actual deployment end with some notes, which can be retrieved later with `helm get notes accounts`.*

If anything goes wrong with this deployment, rollback can be done with this command (see also [`helm rollback`
documentation](https://helm.sh/docs/helm/helm_rollback/)) :

```shell
$ helm rollback accounts
```
