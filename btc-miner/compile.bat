@echo off

REM Defina o caminho para o Boost
set BOOST_PATH=C:\Users\ricar\source\repos\btc-miner\vcpkg_installed\x64-windows\include\boost

REM Defina o caminho para o seu arquivo .cu
set CUDA_FILE=kernel.cu

REM Defina o nome do arquivo de saída
set OUTPUT_FILE=btc-miner.exe

REM Compile o arquivo .cu com o nvcc
nvcc -std=c++17 -I %BOOST_PATH% %CUDA_FILE% -o %OUTPUT_FILE%

REM Verifique se houve erro
if %errorlevel% neq 0 (
    echo Ocorreu um erro na compilacao.
    pause
    exit /b %errorlevel%
)

REM Execute o arquivo .exe gerado
echo Compilacao concluida com sucesso. Agora executando o arquivo...
%OUTPUT_FILE%

REM Aguarde para que você veja a saída antes de fechar
pause
