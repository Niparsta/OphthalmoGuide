FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ["backend/backend.csproj", "backend/"]
RUN dotnet restore "backend/backend.csproj"
COPY backend/ backend/
RUN dotnet publish "backend/backend.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl fontconfig fonts-dejavu-core ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*
ENV TZ=Europe/Moscow
COPY backend/Certificates/Russian_Trusted_Root_CA.crt /usr/local/share/ca-certificates/russian-trusted-root.crt
COPY backend/Certificates/Russian_Trusted_Sub_CA.cer /usr/local/share/ca-certificates/russian-trusted-sub.crt
RUN update-ca-certificates
COPY --from=build /app/publish .
COPY ophthalmology_knowledge.json ./ophthalmology_knowledge.json
COPY backend/Certificates ./Certificates
EXPOSE 5190
ENV ASPNETCORE_URLS=http://+:5190
ENTRYPOINT ["dotnet", "backend.dll"]
