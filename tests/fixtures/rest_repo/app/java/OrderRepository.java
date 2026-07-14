import org.springframework.data.repository.CrudRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource(path = "order")
public interface OrderRepository extends CrudRepository<OrderEntity, Long> {}
