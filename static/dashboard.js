var offset = 0;

function loadMoreData() {
  // Make an AJAX request to get more data
  $.ajax({
    url: '/get_more_data?offset=' + offset, // Replace with the actual endpoint to fetch more data
    type: 'GET',
    success: function (data) {
      if (data.length >= 0) {
        offset += data.length;
        updateTable(data);
      } else {
        // No more data to load, hide the "Read More" button
        $('#read-more-btn').hide();
      }
    }
  });
}

function updateTable(data) {
  var tableBody = $('#id01 tbody');

  for (var i = 0; i < data.length; i++) {
    var row = '<tr>' +
      '<td>' + data[i].area_type + '</td>' +
      '<td>' + data[i].availability + '</td>' +
      '<td>' + data[i].location + '</td>' +
      '<td>' + data[i].bhk + '</td>' +
      '<td>' + data[i].bath + '</td>' +
      '<td>' + data[i].Total_sqft + '</td>' +
      '</tr>';
    tableBody.append(row);
  }
}

// Add a click event to the "Read More" button
$('#read-more-btn').on('click', loadMoreData);