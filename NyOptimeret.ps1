Function Menu {
# Menu koden er lånt af Vagn og ændret for mine behov
    do
    {
        Clear-Host
        Write-Host "
            #----------------------------------------------------------#
            #                 Enkle cmdlet opgaver                     #
            #                                                          #
            #                                                          #
            #   1. Find Brugere på serveren                            #
            #   2. Ændre Password på en bruger på serveren             #
            #   3. Lav bruger, OU og grupper ud fra CSV fil            #
            #                                                          #
            #   0. Slut                                                #
            #                                                          #
            #                                                          #
            #----------------------------------------------------------#
            "

        $hovedmenu = read-host "Indtast valgmulighed"

        switch ($hovedmenu)
        {
            1 {getUsers}
            2 {ChangePassword}
            3 {AdminPromt}

            0 {LukMeny}
            #hvis forkert valg starter man forfra til hovedmenu funktion
            default 
            {
                Write-Host -ForegroundColor red "Forkert valgmulighed"
                sleep 2
            }
        }
    } until ($hovedmenu -eq 0)
}

# denne funktion kigger igennem om bokstavs kombinationer ligner en bruger på serveren 
Function getUsers {
    $letter = Read-Host "Indtast den person du leder efter"

    $filter = "Name -like '$letter*'"

    $users = Get-ADUser -Filter $filter -Properties Name

    if ($users) {
        Write-Host "Users whose names start with '$letter':"
        $users | Format-Table Name, SamAccountName, DistinguishedName -AutoSize
    } else {
        Write-Host "No users found whose names start with '$letter'"
    }

    Read-Host "(Press Enter)"
}
# laver nyt password for brugeren der indtastes
Function ChangePassword {
    $Username = Read-Host "Indtast Username"
    $NewPassword = Read-Host -Prompt "Indtast nyt password"
    Set-ADAccountPassword -Identity $Username -NewPassword (ConvertTo-SecureString -AsPlainText "$NewPassword" -Force)
    
    Write-Host "Password for $Username er ændret"
    Read-Host "(Press Enter)"
}


Function Create {  
    # Prompt brugeren til at indtaste legitimationsoplysninger (brugernavn og adgangskode)
    $credential = Get-Credential

    # Udfør handlinger på en fjerncomputer (localhost) ved hjælp af de angivne legitimationsoplysninger
    Invoke-Command -ComputerName localhost -Credential $credential -ScriptBlock {
        
        # stien hvor CSV filen lægger
        $Path = "C:\Users\Administrator\Documents\User_ACDC.csv"
        # Stien hvor logfilen skal lægges
        $LogPath = "C:\Users\Administrator\Documents\UserCreationLog.txt"

        # Opret logfilen, hvis den ikke allerede findes
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType File
        }

        # Importer Active Directory-modulet for at kunne udføre handlinger på brugerkonti og -enheder
        Import-Module ActiveDirectory

        # Indlæs brugerdata fra CSV-filen
        $Data = Import-Csv $Path

        # Kigger gennem hver bruger i CSV-filen
        foreach ($row in $Data) {
            #For user
            $username = $row.Username  # Hent brugernavn fra CSV-filen
            $password = ConvertTo-SecureString $row.Password -AsPlainText -Force  # Konverter adgangskode til sikker streng
            $Name = $row.Name
            $GivenName = $row.GivenName
            $Surname = $row.Surname

            #For OU
            $Gou = $row.GroupOU
            $Uou = $row.UserOU
            $Oou = $row.OtherOU

            $groupOUs = $Gou -split ","
            $userOUs = $Uou -split ","
            $otherOUs = $Oou -split ","

            #For Groups
            $groupType = $row.GroupType
            $group = $row.Group

        

            #Group OUs
            # Kigger gennem hver OU i $groupOUs-arrayet
            if ($Gou -ne "") {
                for ($i = 0; $i -lt $groupOUs.Count; $i++) {
                    # Tager navnet på OU'en fra strengen/path ved at splitte efter "=" og vælger det næste element ([1])
                    $groupName = ($groupOUs[$i] -split "=")[1]

                    # Laver en tom streng til stien for den nye OU
                    $groupPath = ""

                    # Konstruerer stien for den nye OU ved at gå baglæns gennem arrayet og tilføje hvert element til stien
                    for ($j = $i; $j -ge 0; $j--) {
                        # Hvis $j ikke er det samme som $i, tilføjes et komma for at adskille OUs i stien
                        if ($j -ne $i) {
                            $groupPath += $groupOUs[$j]
                        }
                        # Tilføjer komma til stien, undtagen hvis det er den sidste OU i stien
                        if ($j -lt $i) {
                            $groupPath += ","
                        }
                    }

                    # Opretter den nye OU i Active Directory med det angivne navn og sti
                    New-ADOrganizationalUnit -Name $groupName -Path "$groupPath DC=CVPL1,DC=dk" -ProtectedFromAccidentalDeletion $False  
                }
            }
            # User OU
            # Kigger gennem hver OU i $groupOUs-arrayet
            if ($Uou -ne "") {
                for ($i = 0; $i -lt $userOUs.Count; $i++) {
                # Tager navnet på OU'en fra strengen/path ved at splitte efter "=" og vælger det næste element ([1])
                    $userOUName = ($userOUs[$i] -split "=")[1]
                    # Laver en tom streng til stien for den nye OU
                    $userPath = ""
                    # Konstruerer stien for den nye OU ved at gå baglæns gennem arrayet og tilføje hvert element til stien
                    for ($j = $i; $j -ge 0; $j--) {
                        # Hvis $j ikke er det samme som $i, tilføjes et komma for at adskille OUs i stien
                        if ($j -ne $i) {
                            $userPath += $userOUs[$j]
                        }
                        # Tilføjer komma til stien, undtagen hvis det er den sidste OU i stien
                        if ($j -lt $i) {
                            $userPath += ","
                        }
                    }

                    New-ADOrganizationalUnit -Name $userOUName -Path "$userPath DC=CVPL1,DC=dk" -ProtectedFromAccidentalDeletion $False  
                }
            }
            if ($Oou -ne "") {
                for ($i = 0; $i -lt $otherOUs.Count; $i++) {
                    # Tager navnet på OU'en fra strengen/path ved at splitte efter "=" og vælger det næste element ([1])
                    $otherName = ($otherOUs[$i] -split "=")[1]

                    # Laver en tom streng til stien for den nye OU
                    $otherPath = ""

                    # Konstruerer stien for den nye OU ved at gå baglæns gennem arrayet og tilføje hvert element til stien
                    for ($j = $i; $j -ge 0; $j--) {
                        # Hvis $j ikke er det samme som $i, tilføjes et komma for at adskille OUs i stien
                        if ($j -ne $i) {
                            $otherPath += $otherOUs[$j]
                        }
                        # Tilføjer komma til stien, undtagen hvis det er den sidste OU i stien
                        if ($j -lt $i) {
                            $otherPath += ","
                        }
                    }

                    # Opretter den nye OU i Active Directory med det angivne navn og sti
                    New-ADOrganizationalUnit -Name $otherName -Path "$otherPath DC=CVPL1,DC=dk" -ProtectedFromAccidentalDeletion $False  
                }
            }




            # Splitter hvert enkle path der hvor der er komma
            $UouArray = $Uou.Split(',') | Where-Object { $_ }
            $GouArray = $Gou.Split(',') | Where-Object { $_ }
            # hvis path ikke er tom skal dette statement køre
            if ($UouArray -ne "") {
                # Da Split laver det om til en form for array
                # kan arrayet reverses med Reverse funktionen
                [Array]::Reverse($UouArray)

                # sætter kommaer ind i den nye path
                $UreversedOU = $UouArray -join ','
                # Da det er muligt at placere brugere, OU eller grupper ind i users mappen
                # uden path direkte sættes der it komma ind her. 
                $UreversedOU += ","
            }
            # hvis path ikke er tom skal dette statement køre
            if ($GouArray -ne "") {
                # Da Split laver det om til en form for array
                # kan arrayet reverses med Reverse funktionen
                [Array]::Reverse($GouArray)

                # sætter kommaer ind i den nye path
                $GreversedOU = $GouArray -join ','
                # Da det er muligt at placere brugere, OU eller grupper ind i users mappen
                # uden path direkte sættes der it komma ind her. 
                $GreversedOU += ","
            }

            if (-not (Get-ADUser -Filter "SamAccountName -eq '$username'") -or $username -ne "") {
                # Opret ny bruger i Active Directory med angivne oplysninger
                New-ADUser -SamAccountName $username -Name $Name -GivenName $GivenName -Surname $Surname -AccountPassword $password -Enabled $true -ErrorAction Stop
            }
            if (-not (Get-ADGroup -Filter "SamAccountName -eq '$group'") -or $group -ne "") {
                # Opret ny gruppe i Active Directory med angivne oplysninger
                New-ADGroup -Name $group -SamAccountName $group -GroupCategory Security -GroupScope $groupType -DisplayName $group -Path "$GreversedOU DC=CVPL1,DC=dk" -Description "HEJHEJ"
            }

            # flytter bruger fra mappen users til den mappe de passer til ifølge CSV filen
            Get-ADUser -Identity $username | Move-ADObject -TargetPath "$UreversedOU DC=CVPL1,DC=dk"
            
            # Tilføjer grupper ud fra csv filen til brugeren 
            Add-ADGroupMember -Identity $group -Members $username

            # Log, at brugeren er oprettet succesfuldt
            Add-Content -Path $LogPath -Value "User $username created successfully."
        }  
    }
    Read-Host "(Press Enter)"
}

Function AdminPromt {
    clear-host
    Write-Host "Denne funktion kræver at ingen af de forhenværnede bruger, OUs og eller grupper allerede existere"
    Write-Host "Derudover kræver denne mulighed administrator adgang vil du fortsætte (yes | no)"
    $read = Read-Host "Yes eller No"
    
    # er hvad hosten skriver == yes gå til create funktionen
    if ($Read -eq "yes" -or "y") {Create}
    # er hvad hosten skriver == no gå til Menu funktionen
    elseif ($read -eq "no" -or "n") {Menu}
    # er hvad hosten skriver != yes eller no gå til Prøv igen
    else {AdminPromt}
}

# Kode Lånt af Vagn
Function LukMeny {
    Write-Host 'Tak for i dag😘' 
    sleep 3
    clear-host
}
Menu