long CMSCEPSetup::Install(CMSCEPSetup *this)
{
    // this_00 = this - 8, adjusts for vtable offset.
    // All subsequent ops use this_00 as the real object ptr
    CMSCEPSetup *this_00 = this - 8;
    ClearErrorInformation(this_00);

    // Check 1 - InitializeDefaults() must have run successfully
    // this+0x230 is the isInitialized flag set at the end of InitializeDefaults() (i believe...)
    // If it's 0, the object was never properly initialized - refuse to proceed.
    if (*(int *)(this + 0x230) == 0)
    {
        uVar1   = 0x80040007;  // CO_E_NOTINITIALIZED - COM object not initialized
        logCode = 0x9080073;
    }
    else
    {
        // Check 2 - Required fields must be populated.
        // this+0x220 = pCAConfigString (CA config string)
        // this+0x198 = first RA name field
        // this+0x1c8 = last RA name field
        // All three must be not nlul - i.e. the user has fliled in the wizard pages.
        if ((*(longlong *)(this + 0x220) == 0) ||
            (*(longlong *)(this + 0x198) == 0) ||
            (*(longlong *)(this + 0x1c8) == 0))
        {
            uVar1   = 0x8007000d;  // ERROR_INVALID_DATA - req'd fields missing
            logCode = 0x8e60073;
        }
        else
        {
            // Check 3 - Service account config must be consistent.
            // If this+0x218 (caFound flag) is set AND this+0x1ec (isEnterpriseCA) is set,
            // then a service account must be configured:
            //   this+0x1f8 = service account username - must be not NULL
            //   this+0x200 = service account password - must be non NULL
            // If either is null when both flags are set, the service account
            // configuration is incomplete - refuse to proceed.
            if (((*(int *)(this + 0x218) == 0) || (*(int *)(this + 0x1ec) == 0)) ||
                ((*(longlong *)(this + 0x1f8) != 0 && (*(longlong *)(this + 0x200) != 0))))
            {
                // All checks passed - hand off to DoSetupWork
                uVar1 = DoSetupWork(this_00, in_RDX);
                if (uVar1 == 0) goto LAB_18001ffa8;  // success
                logCode = 0x90f0073;
            }
            else
            {
                // svc account fields missing despite Enterprise CA being configured
                *(undefined4 *)(this + 0x234) = 0x74b; // internal error code
                uVar1   = 0x8007000d; // ERROR_INVALID_DATA
                logCode = 0x8f50073;
            }
        }

        Ordinal_839(logCode, 0x8007000d);
        logCode = 0x90c0073;
    }

// LAB_18001ff9c:
    Ordinal_839(logCode, uVar1);

// LAB_18001ffa8:
    SetErrorInformation(this_00, uVar1);

    // Write final installation status to registry.
    UpdateConfigurationStatusRegistryKey(0x1800949a8); // 0x1800949a8 = 'NDES'
    // I believe this is to tell srv manager that the installation is complete.
    // HKLM:\Software\Microsoft\ADCS\NDES\ConfigurationStatus or something needs to be set to 2 (i forget exactly..)

    // Dispatch through vtable+0x20
    return (**(code **)(*(longlong *)this_00 + 0x20))(
        this_00, uVar1, L"CMSCEPSetup::Install", 0);
}