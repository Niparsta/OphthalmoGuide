FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY bot-workerservice/*.csproj ./
RUN dotnet restore
COPY bot-workerservice/ ./
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/runtime:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["dotnet", "bot-workerservice.dll"]
