import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
  CircularProgress,
  useTheme,
  Chip,
  Button
} from '@mui/material';
import { tokens } from '../../theme';
import Papa from 'papaparse'; // CSV parsing library

const AnomalyTable = () => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);

  const [anomalyData, setAnomalyData] = useState([]);
  const [anomalyCount, setAnomalyCount] = useState(0);
  const [totalCount, setTotalCount] = useState(0);
  const [isLoading, setIsLoading] = useState(false);

  // Define table columns
  const columns = [
    { id: 'timestamp', label: 'Timestamp' },
    { id: 'duration', label: 'Duration' },
    { id: 'protocol_type', label: 'Protocol' },
    { id: 'service', label: 'Service' },
    { id: 'flag', label: 'Flag' },
    { id: 'src_bytes', label: 'Source Bytes' },
    { id: 'dst_bytes', label: 'Destination Bytes' },
    { id: 'anomaly_score', label: 'Anomaly Score' },
    { id: 'is_anomaly', label: 'Is Anomaly' }
  ];

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (!file) return;

    setIsLoading(true);
    
    Papa.parse(file, {
      header: true,
      complete: (results) => {
        const data = results.data;
        const anomalies = data.filter(item => item.is_anomaly === 'true' || item.is_anomaly === true);
        
        setAnomalyData(data);
        setAnomalyCount(anomalies.length);
        setTotalCount(data.length);
        setIsLoading(false);
      },
      error: (error) => {
        console.error("Error parsing CSV:", error);
        setIsLoading(false);
      }
    });
  };

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
        <Typography variant="h5" fontWeight="600">Network Traffic Analysis</Typography>
        <Box display="flex" gap={2}>
          <Chip
            label={`Anomalies: ${anomalyCount}`}
            color="error"
            variant="outlined"
            sx={{ fontWeight: 'bold' }}
          />
          <Chip
            label={`Total Records: ${totalCount}`}
            color="primary"
            variant="outlined"
          />
        </Box>
      </Box>

      <Box mb={2}>
        <Button
          variant="contained"
          component="label"
          disabled={isLoading}
        >
          {isLoading ? 'Loading...' : ''}
          <input
            type="file"
            accept=".csv"
            onChange={handleFileUpload}
            hidden
          />
        </Button>
      </Box>

      {isLoading ? (
        <Box display="flex" justifyContent="center" alignItems="center" p={4} sx={{ backgroundColor: colors.primary[400], height: 300 }}>
          <CircularProgress size={40} sx={{ mb: 2 }} />
          <Typography variant="body1">Loading CSV data...</Typography>
        </Box>
      ) : anomalyData.length > 0 ? (
        <TableContainer component={Paper} sx={{ backgroundColor: colors.primary[400], maxHeight: 600 }}>
          <Table stickyHeader aria-label="anomaly detection table">
            <TableHead>
              <TableRow>
                {columns.map((column) => (
                  <TableCell
                    key={column.id}
                    sx={{
                      backgroundColor: colors.blueAccent[700],
                      color: colors.grey[100],
                      fontWeight: 'bold'
                    }}
                  >
                    {column.label}
                  </TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {anomalyData.map((row, index) => {
                const isAnomalous = row.is_anomaly === 'true' || row.is_anomaly === true;
                return (
                  <TableRow
                    key={index}
                    sx={{
                      backgroundColor: isAnomalous ? `${colors.redAccent[900]}80` : 'inherit',
                      '&:nth-of-type(odd)': {
                        backgroundColor: isAnomalous ? `${colors.redAccent[900]}80` : colors.primary[500]
                      },
                      '&:hover': { backgroundColor: colors.primary[300] }
                    }}
                  >
                    {columns.map((column) => {
                      if (column.id === 'is_anomaly') {
                        return (
                          <TableCell key={column.id}>
                            <Chip
                              label={isAnomalous ? "YES" : "NO"}
                              color={isAnomalous ? "error" : "success"}
                              size="small"
                            />
                          </TableCell>
                        );
                      }
                      return (
                        <TableCell key={column.id}>
                          {column.id === 'anomaly_score' && typeof row[column.id] === 'number' 
                            ? row[column.id].toFixed(2) 
                            : row[column.id]}
                        </TableCell>
                      );
                    })}
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      ) : (
        <Box display="flex" justifyContent="center" alignItems="center" p={4} sx={{ backgroundColor: colors.primary[400], height: 300 }}>
          <Typography variant="body1">
            Please upload a CSV file containing network traffic data
          </Typography>
        </Box>
      )}
    </Box>
  );
};

export default AnomalyTable;