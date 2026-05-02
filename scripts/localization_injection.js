// Sobrescreve a função original de geolocalização do navegador
navigator.geolocation.getCurrentPosition = function(successCallback, errorCallback) {
    var fakePosition = {
        coords: {
            latitude: 35.6895,   // Latitude falsa (Tóquio)
            longitude: 139.6917, // Longitude falsa (Tóquio)
            accuracy: 10         // Margem de erro em metros
        },
        timestamp: Date.now()
    };
    successCallback(fakePosition); // Entrega a posição falsa para o site
};