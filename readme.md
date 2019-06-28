# FingerPrint

This is the driver (or interface) for the fingerprint sensor on my laptop (LG Gram 2018). This script should work on other laptops and even desktops with fingerprint sensors as well.

## Principles

Call Windows Biometric Framework API to interact with the sensor. Technically, you can use the API to 
access any WBF devices, including facial recognition and iris recognition.

## How to use

You can integrate this interface with other command line and GUI programs to serve as an authentication.

```python
myFP = FingerPrint()
try:
    myFP.open()
    print("Please touch the fingerprint sensor")
    if myFP.verify():
        print("Hello! Master")
    else:
        print("Sorry! Man")
finally:
    myFP.close()
```

## Available APIs

- [x] WinBioOpenSession
- [x] WinBioCloseSession
- [x] WinBioIdentify
    * get the information of unit_id, subtype and identity
- [x] WinBioVerify
    * verify using the given identity and subtype
- [x] WinBioLocateSensor
    * get the unit_id by touching your sensor in case you have multiple sensors
    
## To Do
- [ ] WinBioAcquireFocus
- [ ] WinBioReleaseFocus
- [ ] WinBioAsyncOpenSession
- [ ] WinBioCancel
- [ ] WinBioIdentifyWithCallback
- [ ] WinBioVerifyWithCallback
- [ ] `fix the focus issue`
- [ ] `organize Constants`

## Issues

Currently the program needs to be called in the top-level window. So use the command line instead of IDEs to
call the program, otherwise the sensor will ignore your touch.

```text
python fingerprint.py
```

## Reference

- [Windows Biometric Framework](https://docs.microsoft.com/en-us/windows/desktop/api/_secbiomet/)