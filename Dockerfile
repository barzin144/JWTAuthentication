FROM mcr.microsoft.com/dotnet/core/sdk:3.1.402-alpine3.12 AS build-env
WORKDIR /src

COPY ["DataAccess/DataAccess.csproj", "DataAccess/"]
COPY ["Domain/Domain.csproj", "Domain/"]
COPY ["IoCConfig/IoCConfig.csproj", "IoCConfig/"]
COPY ["Service/Service.csproj", "Service/"]
COPY ["WebApi/WebApi.csproj", "WebApi/"]

RUN dotnet restore "WebApi/WebApi.csproj"

COPY . .

WORKDIR "/src/WebApi"

RUN dotnet build "WebApi.csproj" -c Release -o /app

RUN dotnet publish "WebApi.csproj" -c Release -o /app

FROM mcr.microsoft.com/dotnet/core/aspnet:3.1.8-alpine3.12

WORKDIR "/app"

COPY --from=build-env /app .

ENTRYPOINT ["dotnet", "WebApi.dll"]
