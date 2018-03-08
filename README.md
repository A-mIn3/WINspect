## Description

 <pre>  
       WINspect is part of a larger project for auditing different areas of Windows environments.         
    It focuses on enumerating different parts of a Windows machine to identify security weaknesses       
    and point to components that need further hardening. 

 </pre>

## Features

This current version of the script supports the following features :

- Checking for installed security products.
- Checking for DLL hijackability (Authenticated Users security context).
- Checking for User Account Control settings.
- Checking for unattended installs leftovers.
- Enumerating world-exposed local filesystem shares.
- Enumerating domain users and groups with local group membership.
- Enumerating registry autoruns.
- Enumerating local services that are configurable by Authenticated Users group members.
- Enumerating local services for which corresponding binary is writable by Authenticated Users group members.
- Enumerating non-system32 Windows Hosted Services and their associated DLLs.
- Enumerating local services with unquoted path vulnerability.
- Enumerating non-system scheduled tasks.

## TODO-LIST
- Local Security Policy controls.
- Administrative shares configs.
- User-defined COM.
- Suspicious loaded DLLs.
- Established/listening connections.
- Exposed GPO scripts.

## Supported Powershell Version

   This version was tested in a powershell v2.0 environment.
   

## Contributions

You are welcome to contribute and suggest any improvements.
If you want to point to an issue, Please [file an issue](https://github.com/A-mIn3/WINspect/issues).

## Direct contributions

Fork the repository && File a pull request && You are good to go ;)
 
## Need Help

If you have questions or need further guidance on using the tool, please [file an issue](https://github.com/A-mIn3/WINspect/issues). 

## License
This project is licensed under The GPL terms.
