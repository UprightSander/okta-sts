FROM mcr.microsoft.com/dotnet/core/sdk:3.1 AS build-env
WORKDIR /app
COPY okta.pfx /app/okta.pfx

# Copy csproj and restore as distinct layers
COPY *.csproj ./
RUN dotnet restore

# Copy everything else and build
COPY . ./
RUN dotnet publish -c Release -o out

# Build runtime image
FROM mcr.microsoft.com/dotnet/core/sdk:3.1
WORKDIR /app
COPY --from=build-env /app/out .
ENTRYPOINT ["dotnet", "Okta.dll"]
ENV ASPNETCORE_Kestrel__Certificates__Default__Password="supersecret"
ENV ASPNETCORE_Kestrel__Certificates__Default__Path=okta.pfx
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT="Development"
EXPOSE 8080