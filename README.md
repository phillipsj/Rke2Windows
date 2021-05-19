# Rke2Windows

Getting start requires the following installed:

* Vagrant 2.2.x
* Hyper-V


## Vagrant Up

You can run the following to get started. 

```
vagrant up
```

The windows box will come up and check to see if the needed Windows Features are available, if not, then it will install them and require a reboot. You can reboot with the following command.

```
vagrant powershell winworker -c "Restart-Computer"
```

Now we can execute our provision step that will pick up and continue.

```
vagrant up winworker --provision
```
