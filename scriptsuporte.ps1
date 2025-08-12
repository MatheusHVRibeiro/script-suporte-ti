#menu principal 
$operacao = "100"
do{
    Write-Host "Selecione qual opração você deseja"
    Write-Host "1 - limpesa de usuarios"
    Write-Host "2 - erro impressoras"
    Write-Host "3 - desinstalar programa"
    Write-Host "4 - desinstalar impressora"
    Write-Host "5 - desabilita smb 1.0"
    Write-Host "0 - sair"
    $operacao = Read-Host

    switch ($operacao) {
        "1" {Clear-Host; limpesa_de_usuarios}
        "2" {Clear-Host; impressoras_bug_win}
        "3" {Clear-Host; desinstalar_programa}
        "4" {Clear-Host; apagar_impressoeas}
        "5" {Clear-Host; desabilita_smb1}
    }

}while($operacao -ne "0")


function desabilita_smb1{
    # Verifica se está em modo administrador
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        Write-Warning "Este script precisa ser executado como administrador!"
        Exit
    }

    # Desativa os recursos relacionados ao SMB 1.0
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "FS-SMB1" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart

    Write-Host "`nSMB 1.0 foi desativado. Reinicie o computador para concluir a alteração." -ForegroundColor Green
}

function apagar_impressoeas{
    Write-Host "Desinstala impressora"
    Write-Host "Selecione a impressora q deseja desinstalar"
    $impressoras = Get-Printer
    $filtro = $impressoras | Where-Object { $_.Type -ne 'File' }  
    $i = 0
    ForEach($imp in $filtro) {
        Write-Host $i+" - "+$imp.Name
        $i = $i + 1
    }
    Write-Host $i+" - todas"
    $opcao = Read-Host
    if($opcao -eq $i){
        foreach ($imp in $filtro) {
            Remove-Printer -Name $imp.Name
        }
    }else{
        Remove-Printer -Name $filtro[0].Name
    }

}

function desinstalar_programa{
    Write-Host "Desinstala programa"
    # Verifica se está rodando como administrador
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        Write-Warning "Este script precisa ser executado como administrador!"
        Exit
    }

    # Junta os programas de 32 e 64 bits
    $programas = @()
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $paths) {
        $programas += Get-ItemProperty $path |
            Where-Object { $_.DisplayName -and $_.UninstallString } |
            Select-Object DisplayName, UninstallString
    }

    # Remove duplicatas e ordena por nome
    $programas = $programas | Sort-Object DisplayName -Unique

    # Exibe a lista numerada
    for ($i = 0; $i -lt $programas.Count; $i++) {
        Write-Output "$($i): $($programas[$i].DisplayName)"
    }

    # Pede escolha do usuário
    $escolha = Read-Host "`nDigite o número do programa que deseja desinstalar"
    if ($escolha -match '^\d+$' -and $escolha -lt $programas.Count) {
        $prog = $programas[$escolha]
        Write-Host "Desinstalando: $($prog.DisplayName)" -ForegroundColor Yellow

        # Executa o comando de desinstalação
        Start-Process "cmd.exe" "/c $($prog.UninstallString)" -Wait
    } else {
        Write-Host "Escolha inválida." -ForegroundColor Red
    }

}

function impressoras_bug_win{
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 0 /f
}

function limpesa_de_usuarios {
    Write-Host "Limpesa de usuarios"
    Write-Host "Digite o numero de dias de inatividade (defalt 90 dias)"
    [int]$diasInativo = Read-Host
    if($diasInativo -eq 0){
        $diasInativo = 90
    }
    # Caminho dos perfis de usuário
    $perfilPath = "C:\Users"
    # Dias de inatividade
    
    $hoje = Get-Date
    # Lista base de perfis que NÃO devem ser removidos
    $ignorarPerfis = @(
        "Default", "Default User", "Public", "All Users",
        "Administrator", "admin", "desktop.ini"
    )
    # Adiciona usuários locais do computador à lista de ignorados
    $usuariosLocais = Get-LocalUser | Where-Object { $_.Enabled } | Select-Object -ExpandProperty Name
    $ignorarPerfis += $usuariosLocais
    Write-Host "`n=== Verificando perfis com mais de $diasInativo dias de inatividade...`n"
    # Coleta os perfis
    $perfis = Get-ChildItem -Path $perfilPath | Where-Object {
        $_.PSIsContainer -and -not ($ignorarPerfis -contains $_.Name)
    }
    $perfisInativos = @()
    foreach ($perfil in $perfis) {
        $diasSemUso = ($hoje - $perfil.LastWriteTime).Days
        if ($diasSemUso -ge $diasInativo) {
            Write-Host "[INATIVO] $($perfil.Name) - $diasSemUso dias sem uso" -ForegroundColor Yellow
            $perfisInativos += $perfil
        } else {
            Write-Host "[ATIVO  ] $($perfil.Name) - $diasSemUso dias" -ForegroundColor Green
        }
    }
    if ($perfisInativos.Count -eq 0) {
        Write-Host "`nNenhum perfil inativo encontrado com mais de $diasInativo dias.`n"
        pause
        exit
    }
    Write-Host "`nDeseja remover esses $($perfisInativos.Count) perfis inativos? (S/N)"
    $resposta = Read-Host
    # Listas para relatórios
    $removidosComSucesso = @()
    $naoRemovidos = @()
    if ($resposta -eq "S" -or $resposta -eq "s") {
        foreach ($perfil in $perfisInativos) {
            try {
                Write-Host "Removendo $($perfil.FullName)..." -ForegroundColor Red
                Remove-Item -Path $perfil.FullName -Recurse -Force -ErrorAction Stop
                $removidosComSucesso += $perfil.Name
            } catch {
                Write-Warning "Erro ao remover $($perfil.FullName): $_"
                $naoRemovidos += $perfil.Name
            }
        }
        # Relatório final
        Write-Host "`n=== RELATÓRIO FINAL ===`n"
        Write-Host "`n✅ Perfis removidos com sucesso ($($removidosComSucesso.Count)):"
        $removidosComSucesso | ForEach-Object { Write-Host "  - $_" }
        Write-Host "`n❌ Perfis que NÃO foram removidos ($($naoRemovidos.Count)):"
        $naoRemovidos | ForEach-Object { Write-Host "  - $_" }
        Write-Host "`nTotal de perfis analisados para remoção: $($perfisInativos.Count)`n"
    } else {
        Write-Host "`nNenhum perfil foi removido.`n"
    }
    pause
}

