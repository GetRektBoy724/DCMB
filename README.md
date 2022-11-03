# DCMB - Dont Call Me Back
*"I really want to remove AC/AV/EDR's kernel callback, but i dont like working with offsets and/or signature"*. Well, not anymore! DCMB will help you to find those callbacks dynamically. DCMB's objective is to **find** kernel callback list/array **without** using signatures or offset **across multiple Windows version**. This project is not intended to being integrated to your project, instead you should learn the logics thats used on this project. Contributions and bug reports are really appreciated!

# Supported Callback
- Process Creation Callback (Returns PspCreateProcessNotifyRoutine array address)
- Thread Creation Callback (Returns PspCreateThreadNotifyRoutine array address)
- Image Load Callback (Returns PspLoadImageNotifyRoutine array address)
- Registry RW Callback (Returns CallbackListHead doubly linked list address)
- Object Creation Callback (Both Process and Thread object) (Returns PsProcessType's and PsThreadType's CallbackList linked list address)

# Usage
Compile them, enable test signing mode, load it, and view the results through DebugView
![image](https://user-images.githubusercontent.com/41237415/199712912-c06c8b30-cc43-4da6-b2fd-22fc046f2a74.png)
