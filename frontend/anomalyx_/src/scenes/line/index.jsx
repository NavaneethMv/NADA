import { Box } from "@mui/material";
import Header from "../../components/Header";
import CSVLoader from "../../components/CSVLoader";

const Line = () => {
  return (
    <Box m="20px">
      <Header title="Real-time csv data"/>
      <Box height="75vh">
        <CSVLoader />
      </Box>
    </Box>
  );
};

export default Line;
