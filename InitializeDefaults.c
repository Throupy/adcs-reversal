// My attempt to somewhat reverse and de-obfuscate the NDES AD CS role configuration
// Main conclusions
// 0x80070005 (ERROR_ACCESS_DENIED) - gate 1 failure
// 0x80072098 (ERROR_DS_INSUFF_ACCESS_RIGHTS) - gate 3 failure (not in this function, in put_CAInformation)
// 0x80070431 (ERROR_SERVICE_ALREADY_RUNNING) - gate 2 failure
// 0x8007139f (ERROR_NOT_SUPPORTED_ON_SBS) - if ndes already initialised. never seen this in practice, but turns out it's possible

long __thiscall CMSCEPSetup::InitializeDefaults(CMSCEPSetup *this)

{
    // Snip
    ClearErrorInformation(this_00);
    VariantInit((VARIANTARG *)&local_170.n2);

    // this+0x230 is the initialisation flag, set to 1 at the end of a successful
    // InitializeDefaults() call. Not a named field in the original binary, ghidra
    // decompiled it as *(int *)(this + 0x230)
    int isInitialized = *(int *)(this + 0x230);

    // one-shot guard, if not yet initialized, run the init sequence
    if (isInitialized == 0)
    {
        // Reset internal state on CMSCEP setup object back to defaults.
        // called here to ensure a 'clean state' approach beforer the init sequence runs
        Cleanup(this);

        // This is gate 1 - the configuration credential must be a member of BUILTIN\Administrators (s-1-5-32-544)
        // param1=0 selects the local administrators path in IsUserInAdminGroup
        // failure returns ERROR_ACCESS_DENIED (0x80070005) and sets an internal error code at this+0x234
        isUserLocalAdmin = IsUserInAdminGroup(this, 0, in_R8D);
        if (isUserLocalAdmin == 0)
        {
            // this+0x234 is an internal err code field,seemingly, not a named symbol.
            // 0x735 is an internal NDES error identifier logged alongside HRESULT
            *(undefined4 *)(this + 0x234) = 0x735; // internal err code
            logCode = 0x75a0073;
            hresult = 0x80070005; // ERROR_ACCESS_DENIED, passed to wizard
        }
        else
        {
            // GATE 2 - MSCEP registry key must not already exist (indicates already configured)
            // a successful open means NDES has already been configured on this machine.
            // returns ERROR_SERVICE_ALREADY_RUNNING (0x80070431) - misleaing name tho tbh
            // in this context means "NDES already configured, won't reconfigure"
            regOpenResult = RegOpenKeyExW(
                (HKEY)0xffffffff80000002, // HKEY_LOCAL_MACHINE
                L"Software\\Microsoft\\Cryptography\\MSCEP",
                0,        // 0 for standard reg key open, nothing special, required placeholder
                0x20019,  // KEY_READ
                &hMscepKey // output param, snipped.
            );
            if (regOpenResult == 0)
            {
                logCode = 0x7670073;
                hresult = 0x80070431; // ERROR_SERVICE_ALREADY_RUNNING (misleading tho, means already configured)
            }
            else
            {
                // GetVersionExW retrieves the OS version info into local_158
                // used later on by CEPGetCSPInformation to select appropriate
                // CSP defaults for the running OS version
                // Seemingly they re-used the CEP function here, cool.
                osVersionInfo.dwOSVersionInfoSize = 0x11c;
                osVersionOk = GetVersionExW(&osVersionInfo);
                if (osVersionOk == 0)
                {
                    // TODO: What is this going?
                    lastError = GetLastError();
                    hresult = myHError(hresult);
                    logCode = 0x76f0073; // internal NDES diag code passed to LOG_ERROR_INTERNAL
                    caConfigString = NULL;
                }
                else
                {
                    ppDsRoleInfo = &pDsRoleInfo;

                    // this+0x210 is the CA type flag. Not a named field in the binary but
                    // ghidra decompiles it as *(int *)(this + 0x210)
                    // 1 = Enterprise CA, 0 = Standalone CA. Default to enterprise
                    // overridden to Standalone below if DsRoleGetPrimaryDomainInformation
                    // indicates the machine is not domain-joined.
                    caType = 1; // caType = Enterprise

                    // TODO: What's this?
                    *(uint *)(this + 0x1f0) = (uint)(osVersionInfo.szCSDVersion[last] == '\x02');

                    // Query domain role
                    // pDsRoleInfo receives a DSROLE_PRIMARY_DOMAIN_INFO_BASIC struct.
                    // dsRoleResult is a Win32 error code, 0 on success.
                    dsRoleResult = DsRoleGetPrimaryDomainInformation(0);
                    if (dsRoleResult == 0)
                    {
                        // If the machine role has bits 0 and 1 both clear, it's a stnadalone box
                        // (DSROLE_STANDALONE_WORKSTATION=0, DSROLE_STANDALONE_SERVER=2, masked with ~2 catches both)
                        // Override caType to standalone
                        if ((*pDsRoleInfo & 0xfffffffd) == 0)
                        {
                            caType = 0; // caType = Standalone
                        }

                        // Get CSP info
                        hresult = CEPGetCSPInformation(this, 1);
                        if (hresult == 0)
                        {
                            // zero out the RA name fields (populated later by InitializeRAName)
                            // this+0x198 through this.0x1c8
                            *(undefined8 *)(this + 0x198) = 0;
                            *(undefined8 *)(this + 0x1a0) = 0;
                            *(undefined8 *)(this + 0x1a8) = 0;
                            *(undefined8 *)(this + 0x1b0) = 0;
                            *(undefined8 *)(this + 0x1b8) = 0;
                            *(undefined8 *)(this + 0x1c0) = 0;
                            *(undefined8 *)(this + 0x1c8) = 0;

                            // Attempt to locate a CA automatically via ICertConfig2::GetConfig()
                            // over COM. Return the CA config string (CA\CANAme) in local_180
                            // if a CA is found in the AD Enrollment Services container
                            hresult = myGetConfig(this, &caConfigString);

                            if (FAILED(hresult))
                            {
                                // No CA found - not fatal, mark CA config absent
                                // and prompt user to select a CA manually.
                                LOG_ERROR_INTERNAL(0x7930073, hresult);
                                // this+0x218 is the CA found flag. Not a named field in the original
                                // binary — Ghidra decompiles it as *(int *)(this + 0x218).
                                caFound = 0;
                                *(undefined8 *)(this + 0x220) = 0;
                            }
                            else
                            {
                                // CA found - mark present and push config string into object
                                caFound = 1;
                                // GATE 3.5, this put_CAInformation error can bubble up an error:
                                // 0x80072098 (ERROR_DS_INSUFF_ACCESS_RIGHTS)  - this is thrown if the check within this functon fails
                                // the function checks for Enterprise / Domain Admins group membership (enterprise), and local admins for standalone.
                                hresult = put_CAInformation(this, caConfigString, ppDsRoleInfo);

                                if (hresult != S_OK)
                                {
                                    logCode = 0x79b0073;
                                    goto LAB_18001f511;
                                }
                            }

                            // Set UseLocalSystem default.
                            // this+0x1ec is the isEnterpriseCA flag. Not a named field in the original
                            // binary - ghidra decompiles it as *(int *)(this + 0x1ec).
                            // Defaults to VARIANT_TRUE if no CA was found, or if the CA is not
                            // an Enterprise CA. VARIANT_FALSE otherwise.
                            int isEnterpriseCA = *(int *)(this + 0x1ec);
                            variant.n2.vt = VT_BOOL;
                            if ((*(int *)(this + 0x218) == 0) ||
                                (variant._8_2_ = 0, isEnterpriseCA == 0))
                            {
                                variant._8_2_ = VARIANT_TRUE; // 0xffff
                            }
                            hresult = put_UseLocalSystem(this, (tagVARIANT *)&variant.n2);
                            if (hresult == S_OK)
                            {
                                // Default UseChallenge to true.
                                // OTP challenge passwords are enabled by default.
                                // Writes HKLM\Software\Microsoft\Cryptography\MSCEP\UseChallengePassword (DWORD=1).
                                variant._8_2_ = VARIANT_TRUE; // 0xffff
                                hresult = put_UseChallenge(this, (tagVARIANT *)&variant.n2);
                                if (hresult == S_OK)
                                {
                                    // Populate RA name fields (this+0x198 through this+0x1c8)
                                    // with defaults, empty strings or local machine name.
                                    // Actual values set later by the wizard via SetMSCEPSetupProperty.
                                    hresult = InitializeRAName(this, &variant);
                                    if (hresult == S_OK)
                                    {
                                        // Populate default challenge enrollment URls
                                        // into the object from IIS configuration
                                        hresult = InitializeUrls(this, &variant, ppDsRoleInfo, logCode, &hMscepKey);
                                        if (hresult == S_OK)
                                        {
                                            // Init signing key (param=0)
                                            hresult = InitializePrivateKeyInformation(this, 0, (int)ppDsRoleInfo);
                                            if (hresult == S_OK)
                                            {
                                                // Init encryption key (param=1)
                                                hresult = InitializePrivateKeyInformation(this, 1, (int)ppDsRoleInfo);
                                                if (hresult == S_OK)
                                                {
                                                    // Mark successfully initialised
                                                    // subsequent calls rejected by above guard
                                                    *(undefined4 *)(this + 0x230) = 1; // isInitialised = true
                                                    goto LAB_18001f7a0; // success, skip err logging
                                                }
                                                logCode = 0x7b30073;
                                            }
                                            else
                                            {
                                                logCode = 0x7b00073;
                                            }
                                        }
                                        else
                                        {
                                            logCode = 0x7ad0073;
                                        }
                                    }
                                    else
                                    {
                                        logCode = 0x7aa0073;
                                    }
                                }
                                else
                                {
                                    logCode = 0x7a70073;
                                }
                            }
                            else
                            {
                                logCode = 0x7a30073;
                            }
                        }
                        else
                        {
                            logCode = 0x7880073;
                            caConfigString = NULL;
                        }
                    }
                    else
                    {
                        // DsRoleGetPrimaryDomainInformation failed
                        logCode = 0x77d0073;
                        hresult = dsRoleResult & 0xffff | 0x80070000;
                        if ((int)dsRoleResult < 1)
                        {
                            hresult = dsRoleResult;
                        }
                    }
                }
            }
        }
    }
    else
    {
        // Already initialized
        logCode = 0x74e0073;
        hresult = 0x8007139f;
    }
LAB_18001f511:
    LOG_ERROR_INTERNAL(logCode, hresult);
LAB_18001f7a0:
    // Cleamup
    VariantClear((VARIANTARG *)&variant.n2);
    if (pDsRoleInfo != NULL)
    {
        DsRoleFreeMemory();
    }
    if (caConfigString != NULL)
    {
        LocalFree(caConfigString);
    }
    if (hMscepKey != NULL)
    {
        RegCloseKey(hMscepKey);
    }
    SetErrorInformation(this, hresult);
    // disaptch into through vtable+0x20 (error reporting / logging interface)
    return (**(code **)(*(longlong *)this + 0x20))(this, hresult, L"CMSCEPSetup::InitializeDefaults", 0);
    ;
}
