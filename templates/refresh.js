document.addEventListener('DOMContentLoaded', function() {
        let table = document.querySelector('#table')
        function refresh {
            setInterval(function() {
                $(table).load(location.href+ table,"");
                }, 5000);
        }
});