import { useState, useEffect } from "react";
import { Box, Typography, useTheme } from "@mui/material";
import Papa from "papaparse";
import { tokens } from "../theme";

const CSVLoader = () => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);
  const [data, setData] = useState([]);

  // Function to fetch and parse CSV
  const fetchCSV = async () => {
    try {
      const response = await fetch("/data.csv"); // Make sure this file exists
      const reader = response.body.getReader();
      const result = await reader.read();
      const text = new TextDecoder("utf-8").decode(result.value);

      // Parse CSV using PapaParse
      Papa.parse(text, {
        header: true, // Treat first row as headers
        skipEmptyLines: true,
        complete: (result) => {
          setData(result.data);
        },
      });
    } catch (error) {
      console.error("Error fetching CSV:", error);
    }
  };

  // Fetch CSV initially and then every 5 seconds
  useEffect(() => {
    fetchCSV();
    const interval = setInterval(fetchCSV, 5000); // Auto-refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  return (
    <Box p={3} backgroundColor={colors.primary[400]} borderRadius="10px">
      <Typography variant="h5" fontWeight="600" color={colors.grey[100]}>
        Real-Time CSV Data
      </Typography>
      <Box overflow="auto" height="250px" mt={2}>
        <table style={{ width: "100%", borderCollapse: "collapse", border: "1px solid white" }}>
          <thead>
            <tr style={{ backgroundColor: colors.primary[500] }}>
              {data.length > 0 &&
                Object.keys(data[0]).map((key) => (
                  <th key={key} style={{ padding: "8px", border: "1px solid white", color: "white" }}>
                    {key}
                  </th>
                ))}
            </tr>
          </thead>
          <tbody>
            {data.map((row, index) => (
              <tr key={index} style={{ backgroundColor: index % 2 ? colors.primary[600] : colors.primary[700] }}>
                {Object.values(row).map((value, i) => (
                  <td key={i} style={{ padding: "8px", border: "1px solid white", color: "white" }}>
                    {value}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </Box>
    </Box>
  );
};

export default CSVLoader;
