namespace WebApi.ViewModels;

public class ApiResponseViewModel : ApiResponseViewModel<object> { }

public class ApiResponseViewModel<T>
{
	public bool Success { get; set; }
	public string Message { get; set; } = string.Empty;
	public T? Data { get; set; }
}
